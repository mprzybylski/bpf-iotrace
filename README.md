# `bpf-iotrace`
A libbpf-based utility for characterizing the sizes, filesystem locations, and access patterns of an application's filesystem I/O

## Requirements
See [REQUIREMENTS.md](REQUIREMENTS.md)

## Project layout
This project does its best to follow the [Pitchfork Layout](https://api.csswg.org/bikeshed/?force=1&url=https://raw.githubusercontent.com/vector-of-bool/pitchfork/develop/data/spec.bs#tld.external).  Where its guidelines are ambiguous, project-specific interpretations or exceptions shall be listed below.

### `vcpkg`
According to the Pitchfork spec, the [`vcpkg`](https://learn.microsoft.com/en-us/vcpkg/) dependency manager could have been installed as a submodule in the `external` or `tools` directories.  `vcpkg` is installed as a submodule in the `tools` directory in the `bpf-iotrace` project.

## To do:
* Write builder image smoke tests
* GitHub container registry for builder image
* updatecli pipelines to generate automatic builder image update PRs