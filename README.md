# idapro

Provides a low-level interface to IDA Pro via IDC and IDAPython scripts represented as strings.


## Prerequisites

For use of `ida_gtirbexport.py` script, compile the protobuf defintions and place into ida install directory as below.

```
$ protoc -I=./extra --python_out=/path/to/ida_install_dir/python extra/*.proto
```
