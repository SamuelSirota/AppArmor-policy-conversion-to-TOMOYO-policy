# Zoznam

## FIXME

- [x] variables doesnt work if variable has multiple values
- [x] AARE, file globbing doesnt change it
- [x] includes, recursion to include things in the includes

## TODO

- [x] internal representation of the policy
- [x] transform policy to internal representation
- [x] change_profile added
- [x] transform AARE
- [x] teda musis spravit tabulku ktora premeni AA permission na Tomoyo permissions
- [x] transform to tomoyo
- [ ] add link_rule to transformer
- [x] variables and aliases transformer, tomoyo
- [x] include rekurzivne transformer, tomoyo

- [x] vsimol som si pri konverzii do TOMOYO, ze sa mi ako profile name uklada cesta, i think

## Questions

- [x] how do include the include? when i do the policy how??? do I need to have permission to open files everywhere and open it or how???
- [x] co tie tunables and abstractions ktore su default vo vacsine politik, premenne a take globalne povolenia a globalne premenne
- [x] ako sa dostanem k tej celej tomoyo domene? lebo ja mam iba cestu konkretnu nie ako sa execuje ta domena WAH

- mmap pozriet v elixir, nemal by som to moct preniest do tomoyo
- lock v AA suvisi s fcntl, man fcntl
- chroot sa neda riadit teda cez AA
- malo by to citat ten standardny priecinok
- standardne cest /etc/apparmor.d, keby ze mam svoj vlastny tak musim pridat vlastne priecinok (napr. ako v gcc -I a cesty)
- je to v man apparmor.d (include mechanism)
- malo by to tak kaskadovat, najskor aktualny, potom /etc/apparmord.d a potom daco ine, "zoznam priecinkov ktore pozera"
- pri tych prechodoch pouzit tie exceptions
- skusit ze budem mat iba jednu a potom dajak vyskladat tu historiu, to je spojene s change_profile a tiez s tymi roznymi execmi
- si to rozdelit, tie transitions mozu byt zaujimave
- testovanie

## before 17.4.2025

- [ ] abi 4.0 resp pozriet kompatibility asi viem spravit iba pre 1 verziu nie kazdu

- [ ] tieto rules su not done: HAT, Network, mount/unmount/remount, mqueue, io_uring, userns, pivot, ptrace, signal, dbus, unix, rlimit
- [ ] tieto rules netransformujem do TOMOYO: abi_rule, profile flags/attachments, capability, change_profile, network_rule, all_rule, link_rule
- [ ] tieto rules niesu ani saved do internal representation: change_profile, all_rule, capability, link_rule
