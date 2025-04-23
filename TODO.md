# Zoznam

## after 10.4.2024

### FIXME

- [x] variables doesnt work if variable has multiple values
- [x] AARE, file globbing doesnt change it
- [x] includes, recursion to include things in the includes

### TODO

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

- [ ] abi 4.0 resp pozriet kompatibility asi viem spravit iba pre 1 verziu nie kazdu

- [ ] tieto rules su not done: HAT, Network, mount/unmount/remount, mqueue, io_uring, userns, pivot, ptrace, signal, dbus, unix, rlimit
- [ ] tieto rules netransformujem do TOMOYO: abi_rule, profile flags/attachments, capability, change_profile, network_rule, all_rule, link_rule
- [ ] tieto rules niesu ani saved do internal representation: change_profile, all_rule, capability, link_rule
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
- 

- [ ] SPRAV HATS and CHANGE PROFILES