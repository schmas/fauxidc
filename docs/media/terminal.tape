# Terminal recording for the README: start fauxidc, mint a token with the Test API, call /userinfo.
# Run `scripts/readme-media.sh` from the repo root. It builds fauxidc and runs this tape with vhs.

Output docs/media/terminal.gif

Set Shell "bash"
Set Theme "Github"
Set FontSize 16
Set Width 1100
Set Height 460
Set Padding 24
Set TypingSpeed 35ms
Set Framerate 20

# Use the debug build and a short prompt. Show only the fauxidc log lines, not one line per request.
Hide
Type `export PATH="$PWD/target/debug:$PATH" FAUXIDC_LOG=fauxidc=info PS1='$ '`
Enter
Type "clear"
Enter
Show

Type "fauxidc --config docs/media/fauxidc.toml & sleep 1"
Sleep 300ms
Enter
Sleep 2s

Type `TOKEN=$(curl -s localhost:9000/_mock/example/token --json '{"user": "alice"}' | jq -r .access_token)`
Sleep 300ms
Enter
Sleep 1s

Type `echo "${TOKEN:0:64}..."`
Sleep 300ms
Enter
Sleep 1500ms

Type `curl -s localhost:9000/example/userinfo -H "authorization: Bearer $TOKEN" | jq .`
Sleep 300ms
Enter
Sleep 4s

# Stop the server of this tape.
Hide
Type "kill %1; wait"
Enter
Sleep 500ms
