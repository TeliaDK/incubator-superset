from flask_babel import lazy_gettext as _
import json
from superset import app

def dump_bootstrap_data(bootstrap_data, translate_dashboard):
    json_data = json.dumps(bootstrap_data)
    return translate_bootstrap_data(json_data) if translate_dashboard else json_data

def translate_bootstrap_data(json_data):
    def query(path, d):
        for ix, k in enumerate(path):
            if k == "*":
                path = path[ix+1:]
                for entry in d:
                    for res in query(path, entry):
                        yield res
                d = None
                break
            if k in d:
                d = d[k]
            else:
                d = None
                break
        if d:
            yield d

    def translate(selector, data):
        path = selector.split(".")
        _key = path[-1]
        for d in query(path[0:-1], data):
            d[_key] = str(_(d[_key]))
    
    data_dict = json.loads(json_data)
    paths = app.config.get("TRANSLATE_DASHBOARDS_PROPS", [])
    for path in paths:
        translate(path, data_dict)
    return json.dumps(data_dict)