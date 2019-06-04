with open("/root/scripts/gsb_docker/apikeys.conf") as f:
    keys_raw = f.read().split('\n')
    keys_d = dict()
    for i in keys_raw:
        if i is not '':
            keys_d[i.split(':')[0]] = i.split(':')[1]
    print keys_d.get("Google")
    assert keys_d.get("Google") is not None
