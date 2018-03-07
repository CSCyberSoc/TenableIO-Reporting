import collections
"""
Some miscellaneous dict utils
"""

def dictify(obj):
    """
    dictify, makes a dict out of an object and removes the internal stuff
    """
    d = {}
    if not isinstance(obj, dict):
        obj_dict = vars(obj)
    else:
        obj_dict = obj

    for key in frozenset(obj_dict):
        if key.startswith('_'):  # we definitely don't care
            continue
        elif key.endswith('_'):  # in our current set we don't care
            continue
        d[key] = obj_dict[key]
    return d


def flatten_dict(dictionary, parent_key=''):
    """
    flattens any dicts contained in the passed dictionary
    { "key": {"sub_key": "value" }} turns into
    { "key.sub_key": "value" }
    """
    items = []
    for k, v in dictionary.items():
        new_key = parent_key + '.' + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten_dict(v, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)


def update_nested_dict(source, new_data):
    """Helper to recusivly update a nested dict."""
    for key, value in new_data.iteritems():
        if isinstance(value, collections.Mapping):
            source[key] = update_nested_dict(source.get(key, {}), value)
        else:
            source[key] = new_data[key]
    return source