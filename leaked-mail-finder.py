from pyhunter import PyHunter
from itertools import count
import keys  # create your own keys file
import argparse
import time
import requests
import json

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white


class EmailLeaks:
    def __init__(self, domain_name, hunter_api_key, snov_clien_id, snov_client_secret, hibp_api_key):
        self.email_list = set()
        self.domain_name = domain_name
        self.breached_dict = {}  # Breach results are saved in this
        self.paste_dict = {}  # Paste results are saved in this
        self.pwned_dict = {}  # This is the short summary of the data which contains pwned accounts
        self.hunter_api_key = hunter_api_key
        self.snov_clien_id = snov_clien_id
        self.snov_client_secret = snov_client_secret
        self.hibp_api_key = hibp_api_key
        self.hunter_io_mails = []
        self.snov_io_mails = []

    def get_access_token(self):
        params = {
            'grant_type': 'client_credentials',
            'client_id': self.snov_clien_id,
            'client_secret': self.snov_client_secret
        }

        res = requests.post('https://api.snov.io/v1/oauth/access_token', data=params)
        res_text = res.text.encode('ascii', 'ignore')

        return json.loads(res_text)['access_token']

    def domain_search_snovio(self):
        token = self.get_access_token()
        c = count(0)
        flag = True
        while flag:
            params = {
                'access_token': token,
                'domain': self.domain_name,
                'type': 'all',
                'limit': 100,
                'offset': 100 * next(c)
            }

            res = requests.post('https://api.snov.io/v1/get-domain-emails-with-info', data=params)
            res = res.json()
            print(res)
            for each in res["emails"]:
                self.email_list.add(each["email"])
                self.snov_io_mails.append(each["email"])
            flag = True if res["result"] > 0 else False
            time.sleep(1)

    def domain_search_hunter(self):
        hunter = PyHunter(self.hunter_api_key)
        i = 0
        search = hunter.domain_search(self.domain_name, limit=100, offset=100*i)
        while search['emails']:
            search = hunter.domain_search(self.domain_name, limit=100, offset=100*i)
            for item in search['emails']:
                user_mail = item['value']
                self.email_list.add(user_mail)
                self.hunter_io_mails.append(user_mail)
            i += 1
        print("{} emails have been found via hunter.io".format(len(self.hunter_io_mails)))

    def check_breached_email(self):
        """This function uses haveibeenpwned API and checks the e-mail pwned or not. Also, creates an output file with
        pwned e-mails."""
        api_key = self.hibp_api_key
        header = {'hibp-api-key': api_key}
        for mail in self.email_list:
            user_email = mail
            print(C + user_email)
            print(G + '[+]' + C + ' Checking Breach status for ' + W + '{}'.format(user_email), end='')
            rqst = requests.get('https://haveibeenpwned.com/api/v3/breachedaccount/{}'.format(user_email),
                                headers=header, params={'truncateResponse': 'false'}, timeout=10)
            sc = rqst.status_code

            if sc == 200:
                print(G + ' [ pwned ]' + W)
                json_out = rqst.content.decode('utf-8', 'ignore')
                simple_out = json.loads(json_out)
                self.breached_dict[user_email] = simple_out
                self.pwned_dict[user_email] = "pwned"
                for item in simple_out:
                    print('\n'
                          + G + '[+]' + C + ' Breach      : ' + W + str(item['Title']) + '\n'
                          + G + '[+]' + C + ' Domain      : ' + W + str(item['Domain']) + '\n'
                          + G + '[+]' + C + ' Date        : ' + W + str(item['BreachDate']) + '\n'
                          + G + '[+]' + C + ' Fabricated  : ' + W + str(item['IsFabricated']) + '\n'
                          + G + '[+]' + C + ' Verified    : ' + W + str(item['IsVerified']) + '\n'
                          + G + '[+]' + C + ' Retired     : ' + W + str(item['IsRetired']) + '\n'
                          + G + '[+]' + C + ' Spam        : ' + W + str(item['IsSpamList']))
            elif sc == 404:
                print(R + ' [ Not Breached ]' + W)
            else:
                print('\n')
                print(R + '[-]' + C + ' An Unknown Error Occurred')
                print(rqst.text)
            time.sleep(1.5)  # For rate limit of haveibeenpwned API.
        self.hibp_breached_parser()
        # self.save_all()

    def check_pwned_paste(self):
        """This function uses haveibeenpwned API and performs paste search for e-mail addresses. Creates an output file
        with pasted accounts at the end."""
        api_key = self.hibp_api_key
        header = {'hibp-api-key': api_key}
        for mail in self.email_list:
            print(G + '[+]' + C + ' Checking Paste status for ' + W + '{}'.format(mail), end='')
            rqst_paste = requests.get('https://haveibeenpwned.com/api/v3/pasteaccount/{}'.format(mail),
                                      headers=header, params={'truncateResponse': 'false'}, timeout=10)
            sc_paste = rqst_paste.status_code

            if sc_paste == 200:
                print(G + ' [ pasted ]' + W)
                returned_json = rqst_paste.content.decode('utf-8', 'ignore')
                output = json.loads(returned_json)
                self.paste_dict[mail] = output
            elif sc_paste == 404:
                print(R + ' [ Not Pasted ]' + W)
            else:
                print('\n')
                print(R + '[-]' + C + ' An Unknown Error Occurred')
                print(rqst_paste.text)
            time.sleep(1.5)  # For rate limit of haveibeenpwned API.
            self.hibp_paste_parser()

    def save_all(self):
        with open('breached_{}.json'.format(self.domain_name), 'w') as fp:
            json.dump(self.breached_dict, fp, sort_keys=True, indent=4)

    def save_pwned(self):
        with open('short_{}.json'.format(self.domain_name), 'w') as fp:
            json.dump(self.pwned_dict, fp, sort_keys=True, indent=4)

    def save_paste(self):
        with open('paste_{}.json'.format(self.domain_name), 'w') as fp:
            json.dump(self.paste_dict, fp, sort_keys=True, indent=4)

    def hibp_breached_parser(self):
        breached_header = "Email, BreachDate, Description, IsFabricated, IsSensitive, IsVerified, Title\n"
        breached_result = breached_header
        for mail in self.breached_dict:
            for i, field in enumerate(self.breached_dict[mail]):
                email = mail
                breach_date = get_field(self.breached_dict[mail], i, 'BreachDate')
                description = get_field(self.breached_dict[mail], i, 'Description')
                is_fabricated = get_field(self.breached_dict[mail], i, 'IsFabricated')
                is_sensitive = get_field(self.breached_dict[mail], i, 'IsSensitive')
                is_verified = get_field(self.breached_dict[mail], i, 'IsVerified')
                title = get_field(self.breached_dict[mail], i, 'Title')

                entry = "{}|{}|{}|{}|{}|{}|{}\n".format(email, breach_date, description, is_fabricated, is_sensitive,
                                                        is_verified, title)
                breached_result = breached_result + entry

        with open(self.domain_name + "_breached" + '.csv', 'w', encoding='UTF-8') as csv_file:
            csv_file.write(breached_result)

    def hibp_paste_parser(self):
        with open(file2, 'r', encoding='UTF-8') as pFile:
            self.paste_dict = json.load(pFile)
        pasted_header = "Email, Date, Id, Source, Title\n"
        pasted_result = pasted_header
        for mail in self.paste_dict:
            for i, field in enumerate(self.paste_dict[mail]):
                date = get_field(self.paste_dict[mail], i, 'Date')
                identification = get_field(self.paste_dict[mail], i, 'Id')
                source = get_field(self.paste_dict[mail], i, 'Source')
                title = get_field(self.paste_dict[mail], i, 'Title')

                entry = "{}|{}|{}|{}|{}\n".format(email, date, identification, source, title)
                pasted_result = pasted_result + entry

        with open(self.domain_name + "_paste" + '.csv', 'w', encoding='UTF-8') as csv_file:
            csv_file.write(pasted_result)

    def test(self):
        with open('test_file_with_emails', 'r') as fr:
            for line in fr:
                self.email_list.add(line.strip('\n'))


if __name__ == '__main__':
    # Accept domain name from user
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--domain", required=True, help="domain name to look for")
    args = ap.parse_args()

    email_instance = EmailLeaks(args.domain, keys.HUNTER_KEY, keys.SNOV_CLIENT_ID, keys.SNOV_CLIENT_SECRET,
                                keys.HIBP_API_KEY)
    try:
        email_instance.domain_search_hunter()
        email_instance.domain_search_snovio()
        email_instance.check_breached_email()
        email_instance.check_pwned_paste()
    except Exception as e:
        print(str(e))
        with open(args.domain + ".txt", "w", encoding="UTF-8") as fp:
            fp.write("\n".join(email_instance.email_list))
