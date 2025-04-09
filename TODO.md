# Zoznam

## NOT WORKING

- [ ] variables doesnt work if variable has multiple values
- [ ] AARE, file globbing doesnt change it
- [ ] includes, recursion to include things in the includes

## TODO

- [x] internal representation of the policy
- [x] transform policy to internal representation
- [x] change_profile added
- [ ] transform AARE
- [x] teda musis spravit tabulku ktora premeni AA permission na Tomoyo permissions
- [ ] transform to tomoyo
- [ ] zoberiem AppArmorPolicy object a prejdem jednotlive atributy (includes musim rekurzivne, variables tiez spracovat, aliasy tiez spracovat)
  - [ ] potom az mozem menit jednotlive rules v profiloch na tomoyo rules

## Questions

- [ ] how do include the include? when i do the policy how??? do I need to have permission to open files everywhere and open it or how???
- [ ] co tie tunables and abstractions ktore su default vo vacsine politik, premenne a take globalne povolenia a globalne premenne
- [ ] ako sa dostanem k tej celej tomoyo domene? lebo ja mam iba cestu konkretnu nie ako sa execuje ta domena WAH
