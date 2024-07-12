import pickle
import re
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from tld import get_tld


def abnormal_url(url: str) -> int:
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


def process_tld(url):
    try:
        res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        domain = res.parsed_url.netloc  # type: ignore
    except:
        domain = None
    return domain


def httpSecured(url: str) -> int:
    htp = urlparse(url).scheme
    match = str(htp)
    if match == "https":
        return 1
    else:
        return 0


def digit_count(url: str) -> int:
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


def letter_count(url: str) -> int:
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


def shortening_service(url: str) -> int:
    match = re.search(
        "bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"  # type: ignore
        "yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"  # type: ignore
        "short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"  # type: ignore
        "doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"  # type: ignore
        "db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"  # type: ignore
        "q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"  # type: ignore
        "x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"  # type: ignore
        "tr\.im|link\.zip\.net",  # type: ignore
        url,
    )
    if match:
        return 1
    else:
        return 0


def having_ip_address(url: str) -> int:
    match = re.search(
        "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|"  # IPv4
        "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|"  # IPv4 with port
        "((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)"  # IPv4 in hexadecimal
        "(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|"
        "([0-9]+(?:\.[0-9]+){3}:[0-9]+)|"  # type: ignore
        "((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)",  # type: ignore
        url,
    )  # Ipv6
    if match:
        return 1
    else:
        return 0


def load_model():
    with open("saved_steps.pkl", "rb") as file:
        data = pickle.load(file)
    return data


data = load_model()

model = data["model"]
scaler = data["scaler"]


feature = ["@", "?", "-", "=", ".", "#", "%", "+", "$", "!", "*", ",", "//"]
input_cols = [
    "url_length",
    "https",
    "shortening_service",
    "has_ip_address",
    "abnormal_url",
    "digits",
    "letters",
    "@",
    "?",
    "-",
    "=",
    ".",
    "#",
    "%",
    "+",
    "$",
    "!",
    "*",
    ",",
    "//",
]

url_type = {"NON MALICIOUS": 0, "DEFACEMENT": 1, "MALWARE": 2, "MALICIOUS": 3}
type_color = {"green": 0, "blue": 1, "orange": 2, "red": 3}


# Reverse the dictionary to map numbers to URL types
number_to_url_type = {v: k for k, v in url_type.items()}
number_to_type_color = {v: k for k, v in type_color.items()}


def get_url_type(number):
    return number_to_url_type.get(number, "Unknown")


def get_type_color(number):
    return number_to_type_color.get(number, "gray")


def show_predict_page():
    st.title("Malicious URL Detection Using Machine Learning")

    multi = """:gray[*Current Model:*] **Random Forest Classifier**  
    :gray[*Accuracy:*]      **88.94%**  
    :gray[*F1 Score:*]      **0.83**  
    :gray[*Recall:*]        **0.81**
    """

    st.markdown(multi)

    st.markdown(
        "Please Enter URL with protocol specified i.e. :blue-background[https://www.youtube.com]"
    )

    url_input = st.text_input(
        "Enter URL 👇",
        placeholder="https://www.youtube.com",
    )

    check = st.button("Check")
    if check:
        if len(url_input) >= 12:
            test_input = pd.DataFrame([url_input], columns=["url"])
            test_input["url"] = test_input["url"].replace("www.", "", regex=True)
            test_input["url_length"] = test_input["url"].apply(len)
            test_input["domain"] = test_input["url"].apply(lambda x: process_tld(x))
            test_input["https"] = test_input["url"].apply(lambda x: httpSecured(x))
            test_input["shortening_service"] = test_input["url"].apply(
                lambda x: shortening_service(x)
            )
            test_input["has_ip_address"] = test_input["url"].apply(
                lambda x: having_ip_address(x)
            )
            test_input["url"] = test_input["url"].replace("https://", "", regex=True)
            test_input["abnormal_url"] = test_input["url"].apply(
                lambda x: abnormal_url(x)
            )
            test_input["digits"] = test_input["url"].apply(lambda x: digit_count(x))
            test_input["letters"] = test_input["url"].apply(lambda x: letter_count(x))

            for a in feature:
                test_input[a] = test_input["url"].apply(lambda i: i.count(a))

            test_input = test_input[input_cols]

            scaled_test_input = scaler.transform(test_input)
            scaled_test_input = pd.DataFrame(
                scaled_test_input, columns=test_input.columns
            )

            pred = model.predict(scaled_test_input)

            st.markdown(
                f"""Predicted URL Type: :{get_type_color(pred[0])}[{get_url_type(pred[0])}]"""
            )
        else:
            st.markdown(""":red[Please enter a valid url]""")
