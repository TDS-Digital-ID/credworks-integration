# Imported container identities

Each candidate records its own immutable archives and source revision. The result-retry update adds new archives; earlier archives remain unchanged. The existing build
engine identifies each image by its builder OCI index. Loading the archive into a
clean containerd image store identifies it by the included platform manifest;
a classic Docker store identifies it by the image configuration digest.

`config/setup-candidate.json` retains the original `partner` and `application` IDs.
The `Imported` entries are platform manifest digests and the `Config` entries are
configuration digests derived from the same checksum-verified archives. The archive
`index.json` points to each manifest, and that manifest points to its configuration.
Each referenced JSON blob was SHA256 checked. Architecture, source label and runtime
user match the original candidate. The import variants describe the same archive bytes, not another build.

Setup tries only those exact immutable identities for the selected architecture.
It records the available identity in new protected state and inspects architecture,
source revision and runtime user before preparation. A rerun uses the exact saved
identity even if another accepted identity has since become available. If that saved
identity is missing, restore its original image into the engine; setup does not
rewrite the binding or change service identities to work around the error.

These import identities do not qualify another host platform or provide public
HTTPS, phone or hardware-authorization evidence.
