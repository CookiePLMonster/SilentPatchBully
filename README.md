# SilentPatch for Bully: Scholarship Edition

This game, which shares a lot of the internals with GTA games, performs fairly well in its PC incarnation as is.
However, it's more than likely that you have at some point spotted the amount of complaints Windows 10
users have about the game, or maybe you have encountered crashes yourself.

SilentPatch attempts to fix Bully memory management completely, so it behaves in the same way independent
of Windows version. This is not the only fix included, however - most notably, it attempts to improve
gameplay experience by improving frame pacing, as well as fixing a few other issues.

Fixes featured in this plugin:

### Crash and bug fixes
* Collision loading code has been improved, fixing occasional crashes on initial game load
* Fixed game's objects pool usage, fixing possible crashes
* Fixed an occasional crash when starting Nutcrackin' or Music Class
* Fixed numerous instances of memory corruption on game exit
* Fixed an use-after-free in sound streaming code, causing a rare crash when talking to people
* Fixed handle leaks in audio code, preventing handles from accumulating during the game
* Fixed several memory leaks in audio code, preventing out of memory crashes during extended play sessions
* Made memory manager workarounds toggleable via the INI file - disabled by default, to be removed in the future
* Frame Limiter has been made much more precise, so the game should lock at exactly 30FPS now
  (as opposed to stock limiter being prone to dropping frames a lot)
* Fixed an issue where game would use more CPU than required when minimized

### Quality of life improvements
* An option to change FPS cap has been added to SilentPatchBully.ini file (game defaults to 30FPS) with an in game button combo to toggle between 30 fps and 60 fps (SELECT + DPAD DOWN) or F11 on your keyboard.
* Automatic settings configuration (game defaults to 1080p with High Shadows), see .ini file comments for more settings.
* **FILE_FLAG_NO_BUFFERING** flag has been removed from IMG reading functions - potentially speeding up streaming

## Compilation requirements

Project is supposed to build out of the box with Visual Studio 2022.

## Submitting feedback

If you want to report it as a bug (any feedback is very much appreciated), first **ENSURE YOU HAVE AN UNMODDED GAME**
(texture mods are fine, scripts - not so much). You can report a bug (.dmp file + a brief explanation on what
you were doing when the game crashes) in the Issues page.

## Credits

* [P3ti](https://github.com/P3ti) - co-developer
* [TroyWarez](https://github.com/TroyWarez) - co-developer
* [amzy](https://www.twitch.tv/amzy) - testing, overall support
