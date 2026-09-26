# Light Phone III legacy unlock interface

New kernels no longer include the unlock-maintenance interface. Custom installations stay unlocked; stock restoration does not need the interface in that state.

The guide retains support for previously released locked installations. Their `/dev/lp3_unlock` interface stages the existing unlock record with root authorisation: v1 supports slot a, and v2 accepts the tested bootloader pair in either slot order. Neither version protects against firmware changes that remove the underlying unlock method.

The implementation is preserved in Git history at `7ceeb923`. Do not re-enable custom-firmware relocking in the guide.
