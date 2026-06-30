import requests


def lookup_ip(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}"
        )

        data = response.json()

        if data["status"] == "success":

            return {
                "lat": data["lat"],
                "lon": data["lon"],
                "country": data["country"]
            }

    except:
        pass

    return None

import requests


def lookup_my_location():

    try:

        response = requests.get(
            "http://ip-api.com/json/"
        )

        data = response.json()

        if data["status"] == "success":

            return {
                "lat": data["lat"],
                "lon": data["lon"]
            }

    except:
        pass

    return None