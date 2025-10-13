# ctfd-enum

Enumerate and bruteforce [CTFd](https://ctfd.io) registrations and logins.

## Commands

### `register`

Enumerate CTFd registration (registered users, emails, whitelisted domains, registration codes).

#### Usage

```sh
./ctfd-enum.py register [OPTIONS] TARGET
```

#### Options

| Flag                 | Arg    | Description                                 |
|----------------------|:------:|---------------------------------------------|
| `-u`, `--usernames`  | `FILE` | Wordlist of usernames                       |
| `-e`, `--emails`     | `FILE` | Wordlist of emails                          |
| `-d`, `--domains`    | `FILE` | Wordlist of whitelisted domains             |
| `-c`, `--codes`      | `FILE` | Wordlist of registration codes              |
| `-t`, `--threads`    | `NUM`  | Number of concurrent threads (default: 150) |
| `-k`, `--insecure`   | -      | Ignore invalid SSL certificates             |

#### Examples

```sh
# Enumerate existing usernames
./ctfd-enum.py register -u usernames.txt https://ctf.example.com

# Enumerate existing emails and registration code
./ctfd-enum.py register -e emails.txt -c codes.txt https://ctf.example.com
```

### `login`

Bruteforce CTFd login with provided usernames and passwords.

#### Usage

```sh
./ctfd-enum.py login [OPTIONS] TARGET
```

#### Options

| Flag                 | Arg    | Description                                 |
|----------------------|:------:|---------------------------------------------|
| `-u`, `--username`   | `TEXT` | Single username or email                    |
| `-U`, `--usernames`  | `FILE` | Wordlist of usernames or emails             |
| `-p`, `--password`   | `TEXT` | Single password                             |
| `-P`, `--passwords`  | `FILE` | Wordlist of passwords                       |
| `-t`, `--threads`    | `NUM`  | Number of concurrent threads (default: 150) |
| `-k`, `--insecure`   | -      | Ignore invalid SSL certificates             |

#### Examples

```sh
# Single username + password list
./ctfd-enum.py login -u alice -P passwords.txt https://ctf.example.com

# Username and password lists
./ctfd-enum.py login -U users.txt -P passwords.txt https://ctf.example.com
```

## Disclaimer

This tool is for educational and authorized security testing purposes only.

## License

MIT License © 2025 [bjornmorten](https://github.com/bjornmorten)
