import json
import argparse


def get_field(dictionary, element, parameter):
    try:
        return dictionary[element][parameter]
    except KeyError:
        return None


def hibp_parser(file1, file2):
    with open(file1, 'r', encoding='UTF-8') as bFile:
        data = json.load(bFile)
    breached_header = "Email, BreachDate, Description, IsFabricated, IsSensitive, IsVerified, Title\n"
    breached_result = breached_header
    for mail in data:
        for i, field in enumerate(data[mail]):
            email = mail
            breach_date = get_field(data[mail], i, 'BreachDate')
            description = get_field(data[mail], i, 'Description')
            is_fabricated = get_field(data[mail], i, 'IsFabricated')
            is_sensitive = get_field(data[mail], i, 'IsSensitive')
            is_verified = get_field(data[mail], i, 'IsVerified')
            title = get_field(data[mail], i, 'Title')

            entry = "{}|{}|{}|{}|{}|{}|{}\n".format(email, breach_date, description, is_fabricated, is_sensitive,
                                                    is_verified, title)
            breached_result = breached_result + entry

    with open(file1.split('.')[0] + '.csv', 'w', encoding='UTF-8') as csv_file:
        csv_file.write(breached_result)

    with open(file2, 'r', encoding='UTF-8') as pFile:
        data = json.load(pFile)
    pasted_header = "Email, Date, Id, Source, Title\n"
    pasted_result = pasted_header
    for mail in data:
        for i, field in enumerate(data[mail]):
            date = get_field(data[mail], i, 'Date')
            identification = get_field(data[mail], i, 'Id')
            source = get_field(data[mail], i, 'Source')
            title = get_field(data[mail], i, 'Title')

            entry = "{}|{}|{}|{}|{}\n".format(email, date, identification, source, title)
            pasted_result = pasted_result + entry

    with open(file2.split('.')[0] + '.csv', 'w', encoding='UTF-8') as csv_file:
        csv_file.write(pasted_result)


if __name__ == '__main__':
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-f", "--filename", nargs=2, required=True, help="JSON files to parse")
    args = argParser.parse_args()
    parser(args.filename[0], args.filename[1])
