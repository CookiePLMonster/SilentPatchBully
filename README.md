# SilentPatch for Bully: Scholarship Edition

This game, which shares a lot of the internals with GTA games, performs fairly well in its PC incarnation as is.
However, it's more than likely that you have at some point spotted the amount of complaints Windows 10
users have about the game, or maybe you have encountered crashes yourself.

SilentPatch attempts to fix Bully memory management completely, so it behaves in the same way independent
of Windows version. This is not the only fix included, however - most notably, it attempts to improve
gameplay experience by improving frame pacing, as well as fixing a few other issues.

Fixes featured in this plugin:

### Crash and bug fixes
* Crashes occuring on Windows 10 (and potentially on Windows 8.1 and other systems) have been fixed
* Collision loading has been improved, fixing occasional crashes on initial game load
* Frame Limiter has been made much more precise, so the game should lock at exactly 30FPS now
 (as opposed to stock limiter being prone to dropping frames a lot)

### Quality of life improvements
* An option to change FPS cap has been added to SilentPatchBully.ini file (game defaults to 30FPS)
* **FILE_FLAG_NO_BUFFERING** flag has been removed from IMG reading functions - potentially speeding up streaming

## Compilation requirements

Project is supposed to build out of the box with Visual Studio 2017.

## Submitting feedback

Since this is a public beta release, you may encounter crashes. Because of this, MiniDumper utility has
been shipped together with SilentPatch. In case of a crash, a .dmp file will be created in your game directory.

If you want to report it as a bug (any feedback is very much appreciated), first **ENSURE YOU HAVE AN UNMODDED GAME**
(texture mods are fine, scripts - not so much). You can report a bug (.dmp file + a brief explanation on what
you were doing when the game crashes) in the Issues page.

## Credits

* [P3ti](https://github.com/P3ti) - collision loading fix
* [quinnsane](https://www.youtube.com/quinnsane) - testing, overall support
