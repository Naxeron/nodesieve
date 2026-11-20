# Third-party software

## ipregion

The location checks in `nodesieve/location.py` ask the GeoIP providers of the "geoip"
group of [ipregion](https://github.com/vernette/ipregion) by vernette, the way ipregion
asks them: the providers, their addresses and request headers, the demo keys and token
flows, how the exit address is found, and which answers count. They are adapted from
ipregion's commit
[`d431acf`](https://github.com/vernette/ipregion/commit/d431acfdb8146a0d970ff0bb1c23db965b4e4495)
(2026-11-16), which nodesieve ran unmodified as `ipregion.sh` before. ipregion is
distributed under the MIT License:

```text
MIT License

Copyright (c) 2024 Nikita Skryabin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Xray

The [Xray](https://github.com/XTLS/Xray-core) binary is not part of this repository.
The checker downloads it from the project's releases on first run, when Xray is the
core nodes are checked through, and checks it against the SHA-256 published with it.

## Mihomo

The [Mihomo](https://github.com/MetaCubeX/mihomo) binary is not part of this
repository. The checker downloads it from the project's releases on first run, when
Mihomo is the core nodes are checked through.
