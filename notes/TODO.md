# Zoznam

## after 10.4.2024

### FIXED

- [x] variables doesnt work if variable has multiple values
- [x] AARE, file globbing doesnt change it
- [x] includes, recursion to include things in the includes

### DONE

- [x] internal representation of the policy
- [x] transform policy to internal representation
- [x] change_profile added
- [x] transform AARE
- [x] teda musis spravit tabulku ktora premeni AA permission na Tomoyo permissions
- [x] transform to tomoyo
- [x] variables and aliases transformer, tomoyo
- [x] include rekurzivne transformer, tomoyo
- [x] vsimol som si pri konverzii do TOMOYO, ze sa mi ako profile name uklada cesta, i think

### Questions

- [x] how do include the include? when i do the policy how??? do I need to have permission to open files everywhere and open it or how???
- [x] co tie tunables and abstractions ktore su default vo vacsine politik, premenne a take globalne povolenia a globalne premenne
- [x] ako sa dostanem k tej celej tomoyo domene? lebo ja mam iba cestu konkretnu nie ako sa execuje ta domena WAH

### NOTES

- pri tych prechodoch pouzit tie exceptions
- skusit ze budem mat iba jednu a potom dajak vyskladat tu historiu, to je spojene s change_profile a tiez s tymi roznymi execmi
- si to rozdelit, tie transitions mozu byt zaujimave
- testovanie

## before 17.4.2025

- spravil som AARE, opravil tie vars a tiez includes
- bprm_check_security, file_fcntl, fie_ioctl, file_ioctl_compat, file_chroot tieto niesu v AA
- ovela viac ich samozrejme nieje v tomoyo "hooks_used.md" tabulka (mmap, lock)
- lock z apparmor, v tomoyo je fcntl ale to nema samostatne pravidlo ale ostatne pravidla ho pouzivaju cize to netreba riesit
- mmap je podobne v tomoyo rieseny na urovni sucastou file read/execute

FIXME musim spravit testovanie, zoberiem existing policy z apparmoru, prekonvertujem ho do tomoyo a potom ho skusim spustit v tomoyo..

- [x] abi 4.0 resp pozriet kompatibility asi viem spravit iba pre 1 verziu nie kazdu

- [ ] tieto rules su not in grammar: HAT, mount/unmount/remount, mqueue, io_uring, userns, pivot, rlimit
- [ ] tieto rules netransformujem do TOMOYO: abi_rule, profile flags/attachments, capability, network_rule, all_rule, link_rule
- [ ] tieto rules niesu ani saved do internal representation: all_rule, capability, network, ptrace, signal, dbus, unix
- co este?

## po

- networky napr. ze su povolene alebo nie neriesi sa nejak podrobne
- network bindy maybe
- testovanie idealne binarna klasifikacia ako v roderikovej prac
- napr man aa politiku, a moju konverted
- man priecinky do databanky, nejak zistit ci tomoyo politika dovoluje accessy
- adhoc testovanie
- mal by som v databanke mat aj subory naviac, ktore by som nemal mat povolene (true negatives)
- musim vymyslieet, v linuxe mozno existuje prikaz ci subor je otvoritelny s opravneniami len idk ci to kontroluje aj mac nie len dac
- kontroluje aj lsm ale iba inode_perm cize nie path
- treba daco no, aspon popisat aj ked nie implementovat testovanie
- poskytuje tomoyo moznost overit bez spustenia, ani access musime pouzit open lebo ten ma hmm idk
- je tam chaos v tom linuxe (multix os)
- rovnake operacie na oboch aa aj tomoyo
- spomenut, aj testy parsovania
- docstringy pekne formatovat

- [ ] SPRAV HATS and CHANGE PROFILES
- [ ] SPRAV BASE POLICY

## BEFORE 24.4.2025

- man ls (test /usr/share/man** r)
- man -C (/etc/manpath.config r)
- taktiez mu dam nech citat z /etc abo takeho priecinka co by nemal mat pristup
- however <https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor/profiles/extras/usr.bin.man> (man policy Px to <https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor/profiles/extras/usr.lib.man-db.man>) here is most of the permissions /usr/lib/man-db/man
- budem musiet spravit ze ked tam je Px tak to len prida exception policy ze initialize_domain /usr/lib/man-db/man /usr/bin/man
- a potom by mal moj kod hlasit ze treba aj ten druhy policy vytvorit ? idk maaaan
- neviem vsak testovat jednotlive pravidla

- spravim si db cmd prikazov ktore otestuju bezpecnostne politiky
- tieto prikazy spustam cez python script, 3 rozne: apparmor, tomoyo converted, tomoyo learn-mode
- mozme spustat v oboch enforcing aj complain resp v tomoyo enforce a permissive

## Po

- [ ] ak by aplikacia mala nejake svoje testy tak by to mohla vykonat vsetko
- [ ] nejak by som pythonu nasadil ten profil nejak change hat or smh
- [ ] mal by som zoznam suborov a pristupov vramci python scriptu budem otvarat na citanie, zapis... spustit nejaku inu appku z toho etc
- [ ] tieto by som spustil z oboch a potom prirovnal k tomu co apparmor
- [ ] file open() by mal pokryt vacsinu veci
- [ ] mal by som otestovat kazde pravidlo co convertujem
- [ ] nejaka statistika o testovani ze z logov viem zistit pravidla ktore boli testovane resp hitnute
- viem ktore praavidla existuju ale nemam nejake dobre veci na testovanie
- potom by som mal nejak spravit repozitar abo co kde by som dal tie logy a skripty k testovaniu a popis ako som to robil
- popisat v praci aj slepe ulicky... comu sa vyhnut
- nabuduce 30.4. v stredu a potom piatok 9.5.

## pred 30.4.2025

- [x] spravil som link, network teda nemam
- [x] pridat ze Px resp ostatne x pravidla co menia domeny pridat do exception policy tie zmeny domen
- [x] musim spravit ze mi to vyexportne jedno domain_policy a tie exception policy
- [x] tieto dve musim dajak pridat do tomoyo ale nechcem zmazat to co tam uz je

- testing
  - save existing policy
  - load new policy
  - run the test
    - test prida vyvori novy aa/tomoyo policy, ktory vlastne bude ukazovat na sameho seba (podprogram) a spravi aby ten profil zmenil domenu/profil na profile ktory chcem testovat
    - code itself asi podprogram ukazuje napr na usr.bin.man, teraz je podprogram vlastne confined a mozeme ho spustit
      - podprogram moze iterovat vlastne cez domain.conf rules a bude pomocou open() testovat r/w opravnenia
      - okrem toho by sme tam pridali aj rules ktore by nemali byt povolene
      - vystupom je dlhy zoznam ci pravidlo je povolene alebo nie (z domain.conf rules zistime True positive a False positive, z tych co tam nemaju byt True negative a False negative)

## po 30.4.2025

- keby som spravil komplement k true positive tak to bude zbytocne nafuknute
- ze nejake pribuzne subory abo co
- sensitivita, recall, precision, statistika, fscore2 (confusion matrix wiki)

## TODO

- [x] spravit false accessy
  - [x] na AA asi funguje /** na tomoyo ale nie
    - [x] mozno aese skusit ci nemam zle recursive dir globbing
- [x] ioctl skusit bez toho (nebolo to treba v TOMOYO)
- [x] neviem co s tymi accessmi co by mali by a niesu povolene, jednoducho tie opacne accessy

  utorok 6.5.2025
- [x] zacat pisat o programe, kode, algoritme, atd, atd
- [x] spravit mini kodik ktory mi spravi tabulku z tych 2 reportov (aby som aj poslal roderikovi)
  - [x] napisat roderikovi moje "vysledky" z testovania ig atdatd
  - [x] spytat sa ho ci mi cital overleaf

  STREDA+STVRTOK 7-8.5.2025
- [x] vysetril som nezrovnalosti v testing vysledkoch
  - [x] root, na TOMOYO virtualke funguje inak ako na AA a preto None (pokial v TOMOYO dam iba / namiest /** tak denied)
  - [x] vysetrit proc (file read proc:/cpuinfo)
    - aby som nehovoril ze to tam je ak to nestihnem, ale ze to nefunguje abo co
  - [x] ???? /dev/pts to iste ako proc (devpts:)
  - [ ] TEN ROOT ESTE DOVYSETRIT
- [x] pisat dalej v praci
  - [x] IR
  - [x] preprocessing
    - [ ] pridat moznost zmenit relativny priecinok pre includes, asi nie
  - [x] Transformer
  - [x] konverzia na tomoyo 4.5stran treba
    - [x] variables, aliases, globbing, 1 page
    - [x] spomenut aj tabulku, mapping AA to TOMOYO
    - [x] HUPS toto je takmer cele a iba 1.5 strany treba viac toho povymyslat, pozriet repo
    - [x] spomenut aj ENVS (base policy)
  - [x] RESUME
    - [x] spravil som polovicu resume
    - [x] treba este popisat testovanie
  - [x] TOMOYO logging

- spravit si memtest a vypnut v registry, tie adresy v ramke co su zle
- [x] elektronicka priloha k praci, v aise sa nachadza zdrojovy kod k datumu... aktualnu verizu je mozno najst na github...

- [x] ukazkove spustenie, ako prekonvertovat politiku
- stredu o 15:00 14.5.2025
- [x] tie change profiles, domain changes vratit naspat (otocit), pripadne zmenit zmazat whatever pozriet

## PRED 14.5.2025

- [x] spytat sa na to vyhlasnie o povodnom dielo ze som to pisal ja sam...
- dat aj pomenovania na figure hore?
- [x] do zaveru mozem dat ze sme sa mohli viac pohrat s tymi environmental variables
- [x] tabulky 3,4,5 (booktabs??)
- [x] nakonci pred apendixom dat "obsah appendixu ako ma roderik v diplomovke"
- [x] spytaj sa na captions tabulky hore, ostatne dole

## PO

- [x] pridat do uvodu co je v jednotlivych sekciach
- [x] LILLY "however," pridat ciarky pozriet
- [x] v zaver viac opisat viac tie vysledky, f-skore
- [x] access transformer, pridaj listing k minted
- [x] zoznamy listingov a obrazky,
- [x] glossary

- [x] v slovenskych textoch dakmam jednopismenkove slovo dat tam ~ aby neboli nakonci riadku
- [x] hook nie hak
- [x] spustit (execute) moze byt aj ako vykonat
- linuxos.sk
- [x] citacie do rezume(ASI NIE) aj do comparison
- [x] ked mam prvy krat nejake cudzie slovo dam emph a potom uz nemusimm ale mozem
- [x] python davat velke P
- [x] algoritmy, aspon return FIXME
- [x] listing ked je jeden, dva
- [x] zdrojove kody obrazkov dat do prilohy
- [x] zmenit link na github
- [x] pridat popis prilohy (zdrojaky kodu, diagramov)

- [x] CELA IMPLEMENTACIA POUZIVA WE namiesto the code aaaaaaaaaaach