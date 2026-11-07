package accounts

// adminGroups — группы, участники которых администрируют Linux: sudo на Debian
// и Ubuntu, wheel на Fedora и Arch, admin на старых Ubuntu.
var adminGroups = []string{"sudo", "wheel", "admin"}
