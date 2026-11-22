"""Infrastructure preflight: require the test's loopback-only namespace."""
import json
import subprocess
import sys


def main():
    command = ["unshare", "--user", "--map-root-user", "--net", "--", "sh", "-ec",
               "ip link set lo up; exec ip -j link show"]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        print("Infrastructure preflight command:", json.dumps(command), flush=True)
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        if result.returncode != 0:
            raise RuntimeError("unshare/ip exited " + str(result.returncode))
        links = json.loads(result.stdout)
        if len(links) != 1 or links[0]["ifname"] != "lo" or "UP" not in links[0]["flags"]:
            raise RuntimeError("expected only an UP loopback interface")
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print("::error title=CI network isolation unavailable::Required user/network namespace preflight failed. No tests were started.",
              file=sys.stderr)
        print("Infrastructure failure:", error, file=sys.stderr)
        return 1
    print("Infrastructure preflight: loopback-only user/network namespace available")
    return 0


if __name__ == "__main__":
    sys.exit(main())
