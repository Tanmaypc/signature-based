import luaparser


def read_and_parse_lua(filename):
    """Reads a Lua configuration file and parses it using luaparser.

    Args:
        filename (str): The path to the Lua configuration file.

    Returns:
        object: The parsed Lua data structure.

    Raises:
        IOError: If the file cannot be read.
        luaparser.LuaSyntaxError: If the Lua syntax is invalid.
    """

    try:
        with open(filename, 'r') as config:
            lua_code = config.read()
        parsed = luaparser.parse(lua_code)
        return parsed
    except IOError as e:
        raise IOError(f"Error reading Lua file: {e}")
    except luaparser.LuaSyntaxError as e:
        raise luaparser.LuaSyntaxError(f"Invalid Lua syntax: {e}")


# Example usage
try:
    parsed_config = read_and_parse_lua("config.lua")
    # Access data from the parsed config (dictionary, list, etc.)
    print(parsed_config)  # Print the entire parsed structure
except (IOError, luaparser.LuaSyntaxError) as e:
    print(f"Error parsing Lua config: {e}")
