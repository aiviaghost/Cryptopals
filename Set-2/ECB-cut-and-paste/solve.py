from Profile_service import Profile_service
from base64 import b64encode, b64decode


if __name__ == "__main__":
    service = Profile_service()
    enc = service.profile_for("jiwaaaf")
    print("b64_enc:", enc)
    print("enc:", b64decode(enc))
    print("decrypted:", service.parse_profile(enc))
