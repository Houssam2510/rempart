import subprocess

from anthropic import Anthropic

client = Anthropic()


def run_suggestion(task: str) -> str:
    msg = client.messages.create(model="claude-opus-5-5", max_tokens=512, messages=[{"role": "user", "content": task}])
    command = msg.content[0].text
    # rempart-expect: AI-OUTPUT-TO-SINK
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


def summarise(text: str) -> str:
    msg = client.messages.create(model="claude-opus-5-5", max_tokens=512, messages=[{"role": "user", "content": text}])
    summary = msg.content[0].text
    # rempart-safe: AI-OUTPUT-TO-SINK
    print(summary)
    return summary
