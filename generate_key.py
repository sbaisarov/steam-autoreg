import uuid

with open('keys.txt', 'a+') as f:
    id_ = str(uuid.uuid4())
    f.write(id_ + '\n')

print(id_)
