# Zoznam

## FIXME

- [x] variables doesnt work if variable has multiple values
- [ ] AARE, file globbing doesnt change it
- [ ] includes, recursion to include things in the includes

## TODO

- [x] internal representation of the policy
- [x] transform policy to internal representation
- [x] change_profile added
- [ ] transform AARE
- [x] teda musis spravit tabulku ktora premeni AA permission na Tomoyo permissions
- [x] transform to tomoyo
- [ ] add link_rule to transformer
- [ ] variables and aliases transformer, tomoyo
- [ ] network rules transformer, tomoyo
- [ ] change_profile transformer, tomoyo
- [ ] include rekurzivne transformer, tomoyo
  - [ ] potom az mozem menit jednotlive rules v profiloch na tomoyo rules

- [ ] vsimol som si pri konverzii do TOMOYO, ze sa mi ako profile name uklada cesta, i think

## Questions

- [x] how do include the include? when i do the policy how??? do I need to have permission to open files everywhere and open it or how???
- [x] co tie tunables and abstractions ktore su default vo vacsine politik, premenne a take globalne povolenia a globalne premenne
- [x] ako sa dostanem k tej celej tomoyo domene? lebo ja mam iba cestu konkretnu nie ako sa execuje ta domena WAH

- WS_INLINE, treba pridat nove riadky do gramatiky
- zistit ako funguje ten lark, ako robi tie expanzie, preco to nezoberie value ale profile_name
- chceme greedy operator (ktory zozerie vsetko), chceme greedyvost az do konca riadku aby precitalo vsetky variables
- mozno pridat new line nakoniec value definition a pojde maybe (v manuali space separated values)
- mmap pozriet v elixir, nemal by som to moct preniest do tomoyo
- lock v AA suvisi s fcntl, man fcntl
- chroot sa neda riadit teda cez AA
- variable je space separated nie comma separated
- malo by to citat ten standardny priecinok
- standardne cest /etc/apparmor.d, keby ze mam svoj vlastny tak musim pridat vlastne priecinok (napr. ako v gcc -I a cesty)
- je to v man apparmor.d (include mechanism)
- malo by to tak kaskadovat, najskor aktualny, potom /etc/apparmord.d a potom daco ine, "zoznam priecinkov ktore pozera"
- pri tych prechodoch pouzit tie exceptions
- skusit ze budem mat iba jednu a potom dajak vyskladat tu historiu, to je spojene s change_profile a tiez s tymi roznymi execmi
- si to rozdelit, tie transitions mozu byt zaujimave
- testovanie
