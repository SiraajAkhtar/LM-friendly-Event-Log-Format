import sys

# codepage fallback
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

from testing_tool.main import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(
            "\nInterrupted. Leftover test accounts/exclusions (if any) will be offered for "
            "cleanup the next time this tool is run."
        )
        sys.exit(130)
    except EOFError:
        print("\nNo more input received (stdin closed)  -  exiting.")
        sys.exit(1)
