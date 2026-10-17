"""Ask CallGuard a question from the terminal.

Run it with:  uv run scripts/ask.py "Is MiCollab 9.8.1.201 affected by CVE-2024-41713?"
Optional:     --model <Nebius model id>
"""

import sys

from callguard.answer import DEFAULT_MODEL, Answerer


def main():
    args = sys.argv[1:]
    model = DEFAULT_MODEL
    if "--model" in args:
        i = args.index("--model")
        model = args[i + 1]
        del args[i:i + 2]
    question = " ".join(args) or "What is CVE-2024-41713, and are attackers using it?"
    result = Answerer(model).answer(question)
    print(f"Q: {question}\n")
    print(result.text)
    details = f"{result.kind}" + (f" ({result.reason})" if result.reason else "")
    print(f"\n[{details}, {result.seconds} s, {result.tokens} tokens"
          + (f", {result.model}" if result.model else "") + "]")
    if result.unsupported:
        print(f"[warning: cited CVEs that were not in the records: {result.unsupported}]")


if __name__ == "__main__":
    main()
