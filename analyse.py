#!/usr/bin/env python3

import fileinput 
import orjson # https://pypi.org/project/orjson/
import pyhash # https://pypi.org/project/pyhash/
from collections import Counter 
import humanize  # https://pypi.org/project/humanize/
import datetime 
import statistics 
import more_itertools # https://pypi.org/project/more-itertools/
from text_histogram3 import histogram # https://pypi.org/project/text-histogram3/
from pydal import DAL,Field
import tabulate # https://pypi.org/project/tabulate/
fromisoformat = datetime.datetime.fromisoformat 

hasher = pyhash.xx_64()

# teller voor regels
cnt =0
# teller voor activiteiten per fingerprint
fingerprints = Counter()
# teller voor bot activiteiten per bot fingerprint
bots = Counter()
# fingerprints van ingelogde gebruikers
blacklist=Counter()
# laatste activiteit per fingerprint 
last_seen = {}
MAX_BETWEEN_VISITS=datetime.timedelta(hours=4)
# lijst met visit duur per fingerprint 
visits = {}
# eerste timestamps per fingerprint in dezelfde volgorde als visits
visits_start_tss = {}


db = DAL('sqlite://visits.db')
db.define_table('agent',
    Field('fingerprint','integer'),
    Field('ua'),
    Field('ip'),
    Field('is_bot','boolean'),
    #Field('is_blacklisted','boolean'),
)
db.define_table('session',
    Field('fingerprint','integer'),
    Field('ts','datetime'),
    Field('duration','integer'),
    Field('is_blacklisted','boolean'),
)
db.define_table('request',
    Field('fingerprint','integer'),
    Field('ts','datetime'),
    #Field('is_blacklisted','boolean'),
    Field('path'),
    Field('session_id','integer')
)



class SqliteMedian:
    def __init__(self):
        self.values = []
    def step(self, value):
        if value is not None:
          self.values.append(value)
    def finalize(self):
        return statistics.median(self.values) if self.values else None

db._adapter.connection.create_aggregate("median",1,SqliteMedian)
db.define_table('calendar',
                Field('greg_dt', 'date'),
                Field('greg_dow', 'integer'),
                Field('greg_year', 'integer'),
                Field('greg_month', 'integer'),
                Field('greg_day', 'integer'),
                Field('iso_year', 'integer'),
                Field('iso_week', 'integer'),
                Field('iso_dow', 'integer'),
                Field('period', 'integer'),
                Field('unique_period', 'integer'),
                Field('unique_week', 'integer'),
                Field('unique_day', 'integer'),
                )

def setup_calendar(db):
    rows = []
    start = datetime.datetime(year=2021, month=6, day=1)  # 4th of jan is first day of iso year 2010
    unique_period = 0
    unique_week = 0
    db.calendar.truncate()
    for offset_in_days in range(365*5):
        day = start + datetime.timedelta(offset_in_days)
        iso_year, iso_week, iso_day = day.isocalendar()
        if offset_in_days % 28 == 0:
            unique_period += 1
        if offset_in_days % 7 == 0:
            unique_week += 1
        record = dict(
            unique_day=offset_in_days,
            greg_dt=str(day.date()),
            greg_dow=day.weekday(),
            greg_year=day.year,
            greg_month=day.month,
            greg_day=day.day,
            iso_year=iso_year,
            iso_week=iso_week,
            iso_dow=iso_day,
            unique_period=unique_period,
            unique_week=unique_week,
            period=1 + (iso_week // 4)  # make it 1 based, just like iso
        )
        rows.append(record)
        db.calendar.insert(**record)

if db(db.calendar).count() == 0:
    print('istalleren van de calender')
    setup_calendar(db)


db.agent.truncate()
db.session.truncate()
db.request.truncate()


def is_bot(ua):
    ua = ua.lower()
    return 'bot' in ua or len(ua) < 40 or 'rssowl' in ua or 'customer' in ua or 'question' in ua

inserted_agent_fingerprints ={}
for line in fileinput.input(files=['normal.log']): 
    # tel 1 op bij de regels 
    cnt += 1
    
    # laad het json document
    d = orjson.loads(line)

    # als er geen 'req' voorkomt is het een informatie message
    # als 'level' <> 30 dan gaat het niet om een request maar om een warning
    if d['level'] != 30 or 'req' not in d:
        continue 
   # deze gaan we veel benaderen, dus snelle toegang regelen
    req_headers = d['req']['headers']
    # er is niet altijd een user-agent, zo niet: verdacht van bot
    ua = req_headers.get('user-agent','bot')
    # de signature is de hash van de user-agent en het ip adres
    signature = req_headers.get('x-real-ip','?')+':'+ua
    fingerprint = hasher(signature) 
   
    if fingerprint not in inserted_agent_fingerprints:
        # niet eerder geziene fingerprints worden toegevoegd aan de agents database. 
        inserted_agent_fingerprints[fingerprint] = db.agent.insert(
            fingerprint=fingerprint,
            ua=ua,
            ip=req_headers.get('x-real-ip','?'),
            is_bot = is_bot(ua)
        )
    if is_bot(ua):
        # als 'bot' ergens voorkomt in de user-agent dan houden we hier rekening mee
        # tellen we het aantal requests op voor de bot en slaan de rest over 
        # we gebruiker de signature omdat deze kleiner is in het geheugen ipv de ua
        bots[fingerprint] += 1
        continue 
    
    if d['req']['meta']['userId']: 
        # ingelogde gebruikers blacklisten en niet meetellen bij de normale acties 
        # print(orjson.dumps(d,option=orjson.OPT_INDENT_2).decode('utf8'))
        blacklist[fingerprint]=+1
        continue 
    else:
        # 'reguliere' bezoekers: 
        fingerprints[fingerprint]+=1

    # conveer de tijd van de request naar een isoformat zodat we kunnen rekenen
    when = fromisoformat(d['time'].rstrip('Z'))
    # sla de request op 
    db.request.insert(
        fingerprint=fingerprint,
        ts=when,
        path=d['req']['url'],
    )

    if fingerprint not in last_seen: 
        last_seen[fingerprint] = when 
        visits[fingerprint] = [0]
        visits_start_tss[fingerprint]=[when]
    else: 
        previous = last_seen[fingerprint]
        if when - previous  > MAX_BETWEEN_VISITS:
            # dit heeft langer geduurd dan verwacht, dus beshouw als een nieuwe visit
            # begin daarom met een nieuwe duur van 0 seconden 
            visits[fingerprint].append(0)
            visits_start_tss[fingerprint].append(when)
        else: 
            # dit past binnen het frame, dus we gaan last_seen updaten 
            # en tellen de duur bij de laatste visit op 
            visits[fingerprint][-1] += (when-previous).total_seconds()
        last_seen[fingerprint] = when
            
    if cnt % 1000 == 0:
        print(f'@{cnt:8}','\r'*12,end='')
print('lines:',cnt)

print('combineren van duur en starttijden...')
for fp, durations in visits.items():
    start_timestamps = visits_start_tss[fp]
    for dur,when in zip(durations,start_timestamps):
        session_id = db.session.insert(
            fingerprint=fp,
            duration=dur,
            ts=when
        )
        db((db.request.fingerprint==fp) &(db.request.ts==when)).update(session_id=session_id)

print('gaten in logging van sessions bijwerken')
db.executesql('update request set session_id=(select max(session_id) from request r2 where r2.fingerprint = request.fingerprint and r2.ts < request.ts ) where session_id is null;')
print('wijzigingen naar db wegschrijven')
db.commit()

try:
    db.executesql('''
        create index idx_agent_fingerprint
        on agent (fingerprint);
        ''')
    db.executesql('''
        create index idx_session_fingerprint
        on session(fingerprint);
        ''')
    db.executesql('''
        create index idx_request_fingerprint
        on request(fingerprint)
    ''')
except:
    print('no indexes were built')

print('blacklisted fingerprints:',len(blacklist),'met samen',sum(blacklist.values()),'requests')
for fp in blacklist:
    # verwijder de fingerprints van de ooit ingelogde gebruikers 
    # want deze tellen niet meer mee in de statistieken
    del fingerprints[fp]
print('bots:',len(bots),'met samen',sum(bots.values()),'requests')
print('fingerprints:',len(fingerprints),'met samen',sum(fingerprints.values()),'requests')
all_visits = []
total_short_visits = 0
total_single_page_hits = 0
for fingerprint, durations in visits.items():
    total_single_page_hits += len([_ for _ in durations if not _])
    total_short_visits += len([_ for _ in durations if 0< _ < 5])
    all_visits.extend([_ for _ in durations if _ >= 5])
total_number_of_visits=len(all_visits)
print('total number of visits:',total_number_of_visits+total_single_page_hits+total_short_visits)
print('total number of multipage visits:',total_number_of_visits)
print('total number of short visits:',total_short_visits)
print('total number of singlepage visits:',total_single_page_hits)
total_visited_seconds=sum(all_visits)
print('total number of visits:',humanize.precisedelta(datetime.timedelta(seconds=total_visited_seconds)))
print('gemiddelde visit duur:',humanize.precisedelta(datetime.timedelta(seconds=(statistics.mean(all_visits)))))
print('median visit duur:',humanize.precisedelta(datetime.timedelta(seconds=(statistics.median(all_visits)))))
histogram(all_visits)

print()
print('Histogram met mediaan van alle bezoekjes langer dan 5 seconden, zonder bots, zonder machines waarop ooit is ingelogd in ghost, mediaan in minuten, vanaf 1 oktober 2021')
sql = '''select min(greg_dt), count(session.id), count(distinct fingerprint), avg(duration), median(duration/60.0) from calendar left outer join session on greg_dt = date(ts) and duration  > 5 where greg_dt between  date('2021-10-01') and date('now') group by greg_year, greg_month, greg_day'''
date_median = {}
for row in db.executesql(sql):
    if row[4]:
        # ignore nulls
        date_median[row[0]] = row[4]
histogram(date_median.values())

print()
print('Overzicht van mediaan per maand (min 5s, geen bots, geen admins, in minuten)')
sql = '''
select 
    min(greg_dt), 
    count(request.id) as requests, 
    count(distinct session.id) as sessions, 
    count(distinct session.fingerprint) as fingerprints, 
    median(duration/60.0)
from calendar 
    left outer join session on greg_dt = date(session.ts) and duration  >= 5 
    left outer join request on request.session_id = session.id 
where greg_dt between  date('2021-06-01') 
    and date('now') 
group by greg_year, greg_month'''
rows = db.executesql(sql)
print(tabulate.tabulate(rows, headers='Maand;requests;sessies;fingerprints;Mediaan sessie duur (min);'.split(';')))

