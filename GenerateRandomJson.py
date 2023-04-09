#coding=utf-8
import random
import string
import json

def generate_random_key(length=5):
    """生成随机的键"""
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_random_value(length=10):
    """生成随机的值"""
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_random_json(length=10):
    """生成随机的JSON键值对"""
    data = {}
    for i in range(length):
        key = generate_random_key()
        value = generate_random_value()
        data[key] = value
    return json.dumps(data,separators=(',',':'))

print(generate_random_json())
