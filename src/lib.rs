//! Provides a low-level interface to IDA Pro via IDC and IDAPython
//! scripts represented as strings.

use lazy_static::lazy_static;

use std::fs;
use std::io::Write;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum IdaError {
    #[snafu(display("invalid path to IDA executable: {}", path))]
    InvalidPath { path: String },
    #[snafu(display("invalid analysis target: {:?}", path))]
    InvalidTarget { path: PathBuf },
    #[snafu(display("invalid analysis target {:?}; would clobber {:?}", path, clobber))]
    InvalidTargetClobber { path: PathBuf, clobber: PathBuf },
    #[snafu(display("canonicalisation of path failed"))]
    BadCanonicalisation { source: std::io::Error },
}

impl From<std::io::Error> for IdaError {
    fn from(error: std::io::Error) -> Self {
        IdaError::BadCanonicalisation { source: error }
    }
}

/// IDA analysis capability.
#[derive(Debug, PartialEq)]
pub enum Bits {
    Bits32,
    Bits64,
}

/// IDA execution mode.
#[derive(Debug, PartialEq)]
pub enum Mode {
    Headless,
    Graphical,
}

/// IDA script type.
#[derive(Debug, PartialEq)]
pub enum Type {
    IDC,
    Python,
}

lazy_static! {
    static ref CAPABILITIES: Regex =
        Regex::new("^(?:.*[/\\\\])?ida(?P<mode>l|q|w|t)(?P<bits>(?:64)?)(?P<exe>(?:\\.exe)?)$")
            .unwrap();
    static ref WINDOWS_PATH: Regex = Regex::new("^[A-Z]:").unwrap();
}

pub fn windowsify<S: AsRef<str>>(path: S, double_escape: bool) -> String {
    let path = path.as_ref();
    if WINDOWS_PATH.is_match(path.as_ref()) {
        if double_escape {
            path.replace(r"\", r"\\")
        } else { 
            path.to_owned()
        }
    } else {
        // NOTE: all paths are canonicalised, so we expect it to begin with /
        let mut rpath: String = if double_escape {
            String::from(r"Z:\\\\")
        } else {
            String::from(r"Z:\\")
        };
        rpath.push_str(
            if path.starts_with("/") {
                &path[1..]
            } else {
                path
            });
        if double_escape {
            path.replace("/", r"\\")
        } else {
            path.replace("/", r"\")
        }
    }
}

/// An IDA context for interfacing with IDA Pro.
#[derive(Debug, PartialEq)]
pub struct IDA {
    exec: String,
    bits: Bits,
    mode: Mode,
    wine: bool,
    docker_image: Option<String>,
    docker_tag: Option<String>,
    docker_local_dir: Option<PathBuf>,
    docker_mount_dir: Option<String>,
    docker_clobber: bool,
    remove_database: bool,
    script_type: Type,
}

/// IDA implements the core functionality of rida it provides a context with
/// known capabilities upon creation.
impl IDA {
    /// Creates a new context to interface with IDA; the default script type is
    /// IDA, and the generated IDA database shall be removed upon script
    /// termination.
    ///
    /// The capabilities of the IDA context are inferred from the filename of
    /// the given IDA executable. For instance: `idal64` will run headless in
    /// 64-bit mode, whereas `idaq` will run with a graphical interface in
    /// 32-bit mode.
    pub fn new(ida_path: &str) -> Result<Self, IdaError> {
        CAPABILITIES
            .captures(ida_path)
            .map(|caps| IDA {
                exec: ida_path.to_owned(),
                bits: if &caps["bits"] == "" {
                    Bits::Bits32
                } else {
                    Bits::Bits64
                },
                mode: if &caps["mode"] == "l" || &caps["mode"] == "t" {
                    Mode::Headless
                } else {
                    Mode::Graphical
                },
                docker_image: None,
                docker_tag: None,
                docker_local_dir: None,
                docker_mount_dir: None,
                docker_clobber: false,
                wine: !caps["exe"].is_empty(),
                remove_database: true,
                script_type: Type::Python,
            })
            .ok_or(IdaError::InvalidPath {
                path: ida_path.to_owned(),
            })
    }

    pub fn dockerised<R: AsRef<Path>>(
        image: &str,
        tag: &str,
        local: R,
        mount: &str,
        ida_path: &str,
    ) -> Result<IDA, IdaError> {
        Self::new(ida_path).and_then(|i| i.with_docker(image, tag, local, mount))
    }

    /// Sets if the IDA database is removed upon script completion.
    pub fn remove_database(mut self, remove: bool) -> IDA {
        self.remove_database = remove;
        self
    }

    pub fn with_docker<R: AsRef<Path>>(
        mut self,
        image: &str,
        tag: &str,
        local: R,
        mount: &str,
    ) -> Result<IDA, IdaError> {
        let local = local.as_ref();
        self.docker_image = Some(image.to_owned());
        self.docker_tag = Some(tag.to_owned());
        self.docker_local_dir = Some(local.canonicalize()?);
        self.docker_mount_dir = Some(mount.to_owned());
        Ok(self)
    }

    pub fn docker_clobbers(mut self, will_clobber: bool) -> IDA {
        self.docker_clobber = will_clobber;
        self
    }

    /// Sets the script type.
    pub fn script_type(mut self, script_type: Type) -> IDA {
        self.script_type = script_type;
        self
    }

    /// Returns `true` if the IDA instance will run without a GUI (i.e. it
    /// will be headless).
    pub fn is_headless(&self) -> bool {
        self.mode == Mode::Headless
    }

    /// Returns `true` if the IDA instance will support loading 64-bit
    /// binaries.
    pub fn is_64bit(&self) -> bool {
        self.bits == Bits::Bits64
    }

    /// Returns `true` if the IDA instance will be launched from a docker
    /// container.
    pub fn is_dockerised(&self) -> bool {
        self.docker_image.is_some()
    }

    /// Returns `true` if IDA instance will be launched from wine or
    /// wineconsole.
    pub fn is_wine(&self) -> bool {
        self.wine
    }

    /// Runs the script with the contents given as `script` on the `target`
    /// executable.
    pub fn run<T: AsRef<Path>>(
        &self,
        script: &str,
        script_args: Option<&str>,
        target: T,
    ) -> Result<bool, IdaError> {
        let target = target.as_ref().canonicalize()?;
        let mut copied_target = false;
        let mut orig_path = None;

        let mut temp_builder = tempfile::Builder::new();
        temp_builder.prefix("ida");
        temp_builder.suffix(if self.script_type == Type::Python {
            ".py"
        } else {
            ".idc"
        });
        let mut script_file = if let Some(ref dir) = self.docker_local_dir {
            temp_builder.tempfile_in(dir)?
        } else {
            temp_builder.tempfile()?
        };

        script_file.write(script.as_bytes())?;
        script_file.as_file().sync_all()?;

        let (mut cmd, rscript, rtarget) = if self.is_dockerised() {
            let mut cmd = process::Command::new("docker");
            let local_dir = self.docker_local_dir.as_ref().unwrap();
            let mount_dir = self.docker_mount_dir.as_ref().unwrap();
            cmd.args(&[
                "run",
                "--rm",
                "-t",
                "-v",
                &format!("{}:{}", local_dir.display(), mount_dir,),
                &format!(
                    "{}:{}",
                    self.docker_image.as_ref().unwrap(),
                    self.docker_tag.as_ref().unwrap(),
                ),
            ]);
            if !self.is_wine() && self.is_headless() {
                cmd.args(&["-e", "TVHEADLESS=1"]);
            };
            let rscript: String =
                PathBuf::from_iter(&[mount_dir.as_ref(), script_file.path().file_name().unwrap()])
                    .to_string_lossy()
                    .into_owned();

            let rtarget = if let Ok(suffix) = target.strip_prefix(local_dir) {
                let rtarget = PathBuf::from_iter(&[mount_dir.as_ref(), suffix]);
                if self.remove_database {
                    orig_path = Some(target)
                };
                rtarget
            } else {
                let file = target.file_name().ok_or_else(|| IdaError::InvalidTarget {
                    path: target.to_owned(),
                })?;
                let to = PathBuf::from_iter(&[local_dir.as_ref(), file]);
                // disallow clobbering
                if !self.docker_clobber && to.exists() {
                    return Err(IdaError::InvalidTargetClobber {
                        path: target.to_owned(),
                        clobber: to,
                    }
                    .into());
                }
                let rtarget = PathBuf::from_iter(&[mount_dir.as_ref(), file]);
                fs::copy(target, &to)?;
                copied_target = true;
                orig_path = Some(to);
                rtarget
            };
            (cmd, rscript, rtarget)
        } else {
            let mut cmd = process::Command::new("/bin/sh");
            cmd.arg("-c");
            if !self.is_wine() && self.is_headless() {
                cmd.env("TVHEADLESS", "1");
            };
            if self.remove_database {
                orig_path = Some(target.to_owned())
            };
            (
                cmd,
                script_file.path().to_string_lossy().into_owned(),
                target,
            )
        };

        let mut exec_cmd = String::new();

        if self.wine {
            if self.is_headless() {
                exec_cmd.push_str("wineconsole --backend=curses");
            } else {
                exec_cmd.push_str("wine");
            };
            exec_cmd.push(' ');
            exec_cmd.push_str(&windowsify(&self.exec, true));
            let target_str = rtarget.to_string_lossy();
            if script_args.is_some() {
                exec_cmd.push_str(
                    &format!(" -B -A -S\"{} {}\" {}",
                                &windowsify(script, false),
                                script_args.unwrap(), // we windowsify this (if required) in the actual script
                                &windowsify(target_str, true)
                            )
                );
            } else {
                exec_cmd.push_str(
                    &format!(" -B -A -S{} {}",
                                &windowsify(script, true),
                                &windowsify(target_str, true)
                            )
                );
            }
        } else {
            cmd.arg(&windowsify(&self.exec, true));
            let target_str = rtarget.to_string_lossy();
            if script_args.is_some() {
                cmd.args(&[
                    "-A",
                    &format!("-S\"{} {}\"", rscript, script_args.unwrap()),
                    target_str.as_ref(),
                ]);
            } else {
                cmd.args(&["-A", &format!("-S{}", rscript), target_str.as_ref()]);
            }
        }
        cmd.arg(&exec_cmd);
        //println!("Executing command: {:?}", cmd);
        let output = cmd.output()?;

        if copied_target {
            fs::remove_file(orig_path.as_ref().unwrap()).ok();
        };

        if self.remove_database {
            // Can fail, in the case of, e.g., an unpacked database.
            let target_path = format!(
                "{}.{}",
                orig_path.as_ref().unwrap().display(),
                if self.bits == Bits::Bits32 {
                    "idb"
                } else {
                    "i64"
                }
            );
            fs::remove_file(&target_path).ok();
        }

        Ok(output.status.success())
    }
}