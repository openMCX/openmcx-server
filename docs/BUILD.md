# Building OpenMCX

Everything builds in Docker; nothing is installed on the host. The images and what runs in which container are
listed in `docs/IMAGES.md`.

## 1. Development image (once, and when a pinned dependency changes)

```sh
docker build -t openmcx-dev:0.1 -f docker/Dockerfile.dev .
```

Ubuntu 24.04 with the compilers and the libraries the programs link, plus pjsip, wolfSSL and Go built from pinned
sources. The build downloads each source archive itself and checks its SHA-256 (`docker/fetch`); the versions,
URLs and hashes are the build arguments at the top of `docker/Dockerfile.dev`, kept equal to
`dependencies.lock.json` by `tools/check-dependencies.py`. For an offline build, put the archives on a web server
under their lock-file names and add `--build-arg DEPS_MIRROR=https://mirror.example/deps`.

## 2. Server images

```sh
tools/build-images 0.1                       # every target, tagged openmcx-<target>:0.1
docker build --target openmcx-mcptt-server -t openmcx-mcptt-server:0.1 -f docker/Dockerfile .   # one target
```

`docker/Dockerfile` has one build stage (Go services and their tests, the C++ programs and their unit tests, on the
development image) and one runtime target per program:

| Target | Program(s) |
|---|---|
| `openmcx-mcptt-server` | `openmcx-mcptt-server` |
| `openmcx-mcvideo-server` | `openmcx-mcvideo-server` |
| `openmcx-mcdata-server` | `openmcx-mcdata-server` |
| `openmcx-common` | `mcx-common` (one common service per container, `--role`) and `mcx-keytool` |
| `openmcx-http-proxy` | `mcx-http-proxy` |
| `openmcx-user-db` | `mcx-user-db` |
| `openmcx-all` | every program in one image (as before the split; for `--image` and comparisons) |

Each runtime target is Ubuntu 24.04 with only its program's run-time packages, the program stripped of its debug
information (the same `-O2` machine code), and `curl` and Python for the health checks. The build stage is shared,
so building every target compiles once.

### Ubuntu release

Ubuntu 24.04 is the default; 26.04 is supported too:

```sh
tools/build-images --ubuntu 26.04 0.1-u2604   # builds openmcx-dev:0.1-ubuntu26.04 first when missing
```

The pinned base image of each release is in `dependencies.lock.json` (`base_images`; `base_image` is the default,
which the Dockerfiles' `BASE_IMAGE` and `RUNTIME_BASE` defaults must equal, checked by `tools/check-dependencies.py`).
Package names differ between releases (for example `libxml2` / `libxml2-16`, freeDiameter 6 / 7, the OpenH264
version); `docker/packages <release> <part>` lists them for both Dockerfiles. pjsip, wolfSSL and Go are built or
fetched from the same pinned sources on both. By hand:

```sh
docker build -t openmcx-dev:0.1-ubuntu26.04 -f docker/Dockerfile.dev \
  --build-arg BASE_IMAGE=<base_images 26.04> --build-arg UBUNTU=26.04 .
docker build --target openmcx-mcptt-server -t openmcx-mcptt-server:0.1-u2604 -f docker/Dockerfile \
  --build-arg DEV_IMAGE=openmcx-dev:0.1-ubuntu26.04 --build-arg RUNTIME_BASE=<base_images 26.04> \
  --build-arg UBUNTU=26.04 .
```

### Red Hat family (CentOS Stream 10)

`docker/Dockerfile.centos` builds the same targets for RHEL-family clusters, in the manner of OpenAirInterface's
`Dockerfile.<nf>.centos`: CentOS Stream 10 builder (GCC 14; CRB and EPEL 10) and CentOS Stream 10 minimal runtime
(`microdnf`, BaseOS and AppStream only). freeDiameter 1.5.0 and OpenH264 2.4.1 have no EL10 package and are built
from pinned sources (`dependencies.lock.json`); the few libraries the minimal image lacks are copied from the builder,
and each image checks with `ldd` that nothing is missing. Not yet built or run in the lab.

```sh
docker build --target openmcx-mcptt-server -t openmcx-mcptt-server:0.1-centos -f docker/Dockerfile.centos .
```

## 3. Client image (openmcx-client repository)

```sh
linux/tools/build-image -t openmcx-client:0.1 --server ../openmcx-server
```

The client builds against this repository's libraries; the image is a slim Ubuntu image like the server targets,
with OpenH264 for MCVideo.

## 4. SIP core and database images

```sh
docker build -t openmcx-kamailio:6.1.4-2 -f docker/Dockerfile.kamailio .
docker build -t openmcx-sipdb:8.0-1 -f docker/Dockerfile.sipdb .
```

## 5. Lint image

```sh
tools/lint-image          # openmcx-lint:0.1: clang-format, clang-tidy, golangci-lint, ruff (docs/CODING_STYLE.md)
```

## 6. Running the labs

```sh
tools/fetch-dependencies.py                                   # the pinned docker-compose binary the lab tools run
tools/regress.py --images 0.1 --client-image openmcx-client:0.1 --select smoke
tools/regress.py --images 0.1 --client-image openmcx-client:0.1 --all --transport both --jobs 2
```

`--images TAG` gives every container the image of its program (`openmcx-<program>:TAG`); `--image IMAGE` runs every
program from one image (`openmcx-all`, or an image built before the split). Labs are torn down after their last
scenario; `tools/lab-clean` reports anything left (`--yes` removes it).
