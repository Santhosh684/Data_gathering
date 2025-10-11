# ---------------------------------------------
#  gen_bank_json.py
# ---------------------------------------------
import random
import json
import datetime

# ------------------------------------------------------------------
# 1.   Settings – how many records, which folders & extensions?
NUM_RECORDS = 250                       # <-- change this value to generate more or fewer rows
EXTENSIONS    = ['.xlsx', '.pdf', '.csv', '.docx', '.xls', '.txt']
PATHS         = [
    'C:/BankData/Transactions/',
    'C:/BankData/Loans/',
    'C:/BankData/CreditCards/',
    'C:/BankData/Accounts/',
    'C:/BankData/Rates/',
    'C:/BankData/Inversions/',
    'C:/BankData/CustomerService/',
    'C:/BankData/Deposits/',
    'C:/BankData/Schedules/',
    'C:/BankData/Lends/',
    'C:/BankData/Mortgages/',
    'C:/BankData/Pensions/'
]
SENSITIVITY   = ['high', 'medium', 'low']
# ------------------------------------------------------------------
def random_date(start='2025-01-01T00:00:00',
                end  ='2025-12-31T23:59:59'):
    """
    Return a string in ISO‑8601 format.
    """
    st = datetime.datetime.strptime(start, "%Y-%m-%dT%H:%M:%S")
    et = datetime.datetime.strptime(end  , "%Y-%m-%dT%H:%M:%S")
    # random timestamp inside the period
    delta   = (et - st).total_seconds()
    rand_sec = random.randint(0, int(delta))
    rnd_dt   = st + datetime.timedelta(seconds=rand_sec)
    return rnd_dt.strftime("%Y-%m-%dT%H:%M:%S")

# ------------------------------------------------------------------
records = []
for i in range(NUM_RECORDS):
    # choose a random folder and extension
    path     = random.choice(PATHS)
    ext      = random.choice(EXTENSIONS)

    # build a file name – we keep the pattern <domain>_<date>.<ext>
    date_part = datetime.datetime.now().strftime("%Y-%m-%d")
    fname   = f"{path.split('/')[-2]}_{i:04d}{ext}"          # e.g. 'Loans_0001.pdf'
    record  = {
        "filename"     : fname,
        "extension"    : ext,
        "filesize_kb"   : random.randint(200, 2500),            # realistic size in KB
        "file_path"    : path,
        "date_modified": random_date(),
        "sensitivity"  : random.choice(SENSITIVITY)
    }
    records.append(record)

# ------------------------------------------------------------------
with open('master-data.json', 'w') as f:
    json.dump(records, f, indent=4, ensure_ascii=False)   # pretty‑print
print(f'Generated {NUM_RECORDS} rows → master-BdataB.json')
