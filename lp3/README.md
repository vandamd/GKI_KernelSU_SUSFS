# Light Phone III unlock maintenance interface

Experimental, not yet device-validated. Do not publish a firmware release or
relock a device based on compilation alone.

This replaces the temporary broad SELinux profile used to stage the existing
Light Phone III unlock certificate. It does not repair the manufacturer's
bootloader trust model or provide GrapheneOS-equivalent security.

## Boundary

`/dev/lp3_unlock` is a root-owned 0600 miscellaneous character device. Each read
and write requires effective UID 0 and CAP_SYS_RAWIO in the initial user
namespace. The user must have authorised root access separately. It is not
limited to ADB Shell: another authorised root process can use the same operation.

The single write operation accepts exactly 4136 bytes, in one write syscall:

- 8 bytes: ASCII `LP3ULK1\n`.
- 32 bytes: binary SHA-256 of the full original 128 KiB mfd partition.
- 4096 bytes: the unlock record generated and signature-verified by the browser.

There is no caller-controlled path, partition, offset, length, policy switch or
command. The driver resolves fixed GPT labels using the kernel's partition
lookup. It requires both tested ABL hashes and sizes, an enabled on-disk OEM
unlock permission, the expected mfd size, a matching original partition hash,
and the empty record markers. It bounds the certificate envelope and padding.
It does not cryptographically verify the certificate itself; the browser and
bootloader perform that verification.

It writes one aligned 4 KiB block at offset 0x3000, flushes it, and reads back the
entire partition to verify that all other bytes are unchanged. Once any write
is attempted, the interface rejects further attempts for the rest of that boot,
including after I/O errors. Errors are not a reason to reboot and retry: retain
the backup and investigate any uncertain write first.

Block I/O is performed inside this fixed operation. Baseband Guard and SELinux
remain enabled; ordinary root partition writes keep their existing restrictions.
Root is already trusted by this firmware, including the ability to manage root
profiles. This interface does not claim to contain a malicious fully privileged
root process.

The driver cannot make power loss atomic or exclude all trusted firmware writers.
It does not write FRP, change the bootloader lock state, erase user data, or
reboot. Android's OEM-unlock setter remains separate. The bootloader's physical
confirmation and data wipe remain mandatory.

## Build and validation

The fork enables this only for LP3-branded ReSukiSU android12-5.10.198 / 2024-01
builds with BBG. BBG is pinned to the revision used in the previously tested
build. Existing release images do not acquire this interface through a website
update; they need a new, validated and signed boot/vbmeta pair.

Before release, validate permission denial for unprivileged callers, wrong OEM
permission, unsupported ABLs, invalid request size/envelope, stale original hash,
and a nonempty record. Confirm rejected inputs leave mfd unchanged. Exercise the
successful path on an unlocked phone first, including full readback, ordinary
write denial, and second-attempt refusal. Then validate the signed locked boot,
physical unlock, data wipe, stock restoration and green verified boot. Keep the
existing stock images and manual recovery procedure available throughout.
