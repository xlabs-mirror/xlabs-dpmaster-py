# get_xlabs_servers

A script which returns a full server list and metrics for all of the games (IW4x, IW6x, and S1x) developed by the [X Labs Project](https://github.com/XLabsProject).
## License

[MIT License](LICENSE)

## Requirements

- Python (3.10+)
## Usage

The script may be downloaded directly from GitHub, or you may download a ZIP or clone the repository.

Run the script with Python: `python get_xlabs_servers.py`

The output of the script is a `xlabs_servers.json` file which is written to the working directory.

## Output File

The output file is a JSON file. The top depth specifies the particular game (and in the case of S1x, the gamemode):
```
{
    "IW4x": ...
    "IW6x": ...
    "S1x (Multiplayer)": ...
    "S1x (Horde)": ...
    "S1x (Zombies)": ...
}
```
Each of these elements contains a dictionary with the following objects:
| Key Name     | Description                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------- |
| bot_count    | The number of bots on all servers for that game                                                             |
| client_count | The number of clients connected on all servers for that game                                                |
| server_count | The number of servers that responded to getInfo requests                                                    |
| server_list* | A dictionary of all the servers (that responded to getInfo requests) and all of their collected information | 
| timestamp    | A timestamp of when the data was finished compiling                                                         |

\* The JSON objects contained within `server_list` are all stored as strings. Each of the tokens are documented at the top of the script in an `INFO_RESPONSE_KEYS` list.

## Authors

- [@JoelColby](https://www.github.com/JoelColby)
