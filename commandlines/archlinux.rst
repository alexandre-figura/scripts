=======================
Archlinux Command-Lines
=======================

Upgrading OS
============

In ``~/.config/fish/functions/pacu.fish``::

    function pacu
        pacaur -Syu; sudo pacman -Rns (pacman -Qdtq); sudo paccache -r
    end
