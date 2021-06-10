from Profile_service import Profile_service
from base64 import b64encode, b64decode


"""
goal:  
<---16 bytes---> <---16 bytes---> <---16 bytes--->
email=aaaaaaaaaa aaa&uid=10&role= admin 11 padding
<-------------------------------> <-------------->
            aligned                 admin_padding


how to make admin_padding
<---16 bytes---> <---16 bytes---> <---16 bytes---> <---16 bytes--->
email=aaaaaaaaaa admin\x0b...\x0b &uid=10&role=use r\x0f.......\x0f
                 <-------------->
                   admin_padding
"""

service = Profile_service()


user_1 = service.profile_for("a" * 13)
aligned = b64decode(user_1)[ : 32]


user_2 = service.profile_for("a" * 10 + "admin" + "\x0b" * 11)
admin_padding = b64decode(user_2)[16 : 32]


crafted_user = b64encode(aligned + admin_padding)

print(f"Crafted admin profile: {service.parse_profile(crafted_user)}")
# {'email': 'aaaaaaaaaaaaa', 'uid': '10', 'role': 'admin'}
