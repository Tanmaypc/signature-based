from re import findall
from copy import deepcopy


def equality_check(other_, self_, normal=True):
    """
    Check inequality based on comparison rules.

    Args:
        other_ (str): The value to compare against.
        self_ (str): The value to compare.
        normal (bool): If True, perform normal inequality check. If False, handle special cases.

    Returns:
        bool: True if inequality holds, False otherwise.
    """
    if normal:
        # Handle special case where protocol is 'IP' and self_ is 'TCP' or 'UDP'
        if other_ == 'IP' and self_ in ['TCP', 'UDP']:
            return False
        else:
            # Perform normal inequality check
            return self_ == other_[1:] if other_[0] == '!' else self_ != other_
    else:
        # Handle case where self_ is 'any'
        if self_ == 'any':
            return False
        split = other_.split('!')
        # Handle range comparison
        if '-' in other_:
            split_split = split[-1].split('-')
            min_ = split_split[0][1:]
            max_ = split_split[1][:-1]
        else:
            min_ = split[-1]
            max_ = split[-1]

        other_ = range(int(min_), int(max_) + 1)
        try:
            self_ = int(self_)
        except ValueError:
            print(f"No meaningful comparison / TODO: {self_}")
            return True
        else:
            return (len(split) == 1 and self_ not in other_) or \
                (len(split) == 2 and self_ in other_)


def switch_directions(signature):
    """
    Switch source and destination in a signature.

    Args:
        signature: The signature object to switch directions for.

    Returns:
        tuple: Two signature objects with switched directions.
    """
    srcdst = deepcopy(signature)
    srcdst.dir = '->'

    dstsrc = deepcopy(signature)
    dstsrc.dir = '->'
    dstsrc.srcIP = dstsrc.dstIP
    dstsrc.srcPort = dstsrc.dstPort
    dstsrc.dstIP = srcdst.srcIP
    dstsrc.dstPort = srcdst.srcPort

    return srcdst, dstsrc


def num_of_layers(packet):
    """
    Count the number of layers in a packet.

    Args:
        packet: The packet object to count layers for.

    Returns:
        int: The number of layers in the packet.
    """
    return len(findall('[|]', packet.__repr__()))
