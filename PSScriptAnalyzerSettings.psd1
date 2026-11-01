@{
    # scripts/check.sh fails the check on Error findings only. Warnings are listed but do not fail it.
    # Tighten this once the current warnings have been reviewed.
    Severity     = @('Error', 'Warning')

    ExcludeRules = @(
        # Interactive prompts and progress are written to the host by design.
        'PSAvoidUsingWriteHost'
    )
}
