from Profile_service import Profile_service
from base64 import b64encode, b64decode


"""
Standard format:
email={user controlled data}&uid=10&role=user


Goal:  
<---16 bytes---> <---16 bytes---> <---16 bytes--->
email=aaaaaaaaaa aaa&uid=10&role= admin\x0b...\x0b
<-------------------------------> <-------------->
            aligned                 admin_padding


How to make admin_padding
<---16 bytes---> <---16 bytes---> <---16 bytes---> <---16 bytes--->
email=aaaaaaaaaa admin\x0b...\x0b &uid=10&role=use r\x0f.......\x0f
                 <-------------->
                   admin_padding

Explanation:
Because the key is constant and ECB is used any combination of 
ciphertext blocks is valid, even if they come from different profiles. 
We can then carefully choose our email (whatever field you control, could
be username in another challenge) so that the plaintext ends with "role=". 
We then craft another plaintext containg the word "admin" and we make sure 
to include valid PKCS#7 padding after "admin". 
"""

service = Profile_service()


user_1 = service.profile_for("a" * 13)
aligned = b64decode(user_1)[ : 32]


user_2 = service.profile_for("a" * 10 + "admin" + "\x0b" * 11)
admin_padding = b64decode(user_2)[16 : 32]


crafted_user = b64encode(aligned + admin_padding)

print(f"Crafted admin profile: {service.parse_profile(crafted_user)}")
# {'email': 'aaaaaaaaaaaaa', 'uid': '10', 'role': 'admin'}
