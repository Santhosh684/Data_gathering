# --------------------------------------------------------------
#  gen_health_json.py – create 250 healthcare‑industry rows
# --------------------------------------------------------------

import json, random, datetime

# ------------------------------------------------------------------
NUM_ROWS        = 250                       # ← change to any other size you need
EXTENSIONS      = ['.xlsx', '.pdf', '.csv',
                   '.docx', '.xls', '.txt']
FOLDERS         = [
    'C:/Healthcare/Patients/',
    'C:/Healthcare/LabResults/',
    'C:/Healthcare/Insurance/',
    'C:/Healthcare/StaffSchedules/',
    'C:/Healthcare/Meetings/',
    'C:/Healthcare/Maintenance/',
    'C:/Healthcare/PublicInfo/Menu/',
    'C:/Healthcare/PublicInfo/Parking/',
    'C:/Healthcare/PublicInfo/Notices/',
    'C:/Healthcare/Internal/Protocols/'
]
SENSITIVITY     = ['high', 'medium', 'low']
# ------------------------------------------------------------------
def _rand_date(start='2025-01-01T00:00:00',
                end  ='2025-12-31T23:59:59'):
    """
    Return a random ISO‑8601 timestamp inside the given window.
    """
    st = datetime.datetime.strptime(start, "%Y-%m-%dT%H:%M:%S")
    et = datetime.datetime.strptime(end  , "%Y-%m-%dT%H:%M:%S")
    delta   = (et - st).total_seconds()
    rnd_sec = random.randint(0, int(delta))
    return (st + datetime.timedelta(seconds=rnd_sec)).strftime("%Y-%m-%dT%H:%M:%S")

# ------------------------------------------------------------------
rows = []
for i in range(NUM_ROWS):
    folder   = random.choice(FOLDERS)
    ext      = random.choice(EXTENSIONS)

    # 1. build a file name – keep the same style as your example
    fname = f"{folder.split('/')[-2]}_{i:04d}{ext}"          # e.g. 'Patients_0007.pdf'

    rows.append({
        "filename"     : fname,
        "extension"    : ext,
        "filesize_kb"   : random.randint(200, 2500),   # realistic KB size
        "file_path"    : folder,
        "date_modified": _rand_date(),
        "sensitivity"  : random.choice(SENSITIVITY)
    })

# ------------------------------------------------------------------
with open('master-data.json', 'w') as fh:
    json.dump(rows, fh, indent=4, ensure_ascii=False)

print(f'✅ Generated {NUM_ROWS} rows → master-HdataH.json')

