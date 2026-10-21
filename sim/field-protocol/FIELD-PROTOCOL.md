# Field protocol

What you do with your phones. Everything in this project that is a real
measurement rather than a model comes from here, so the discipline matters
more than the effort.

You need 4 or 5 devices, mixed iOS and Android. Four is the minimum that can
measure 3 hops, because a 3-hop path needs 4 radios. Two devices can only
measure one link.

## Before you leave

1. Install Bridgefy from the App Store / Play Store on every device. Do not
   update it mid-campaign; note the version per device.
2. Install our instrumented build on every device. It runs in field-test mode:
   it logs every radio event with a timestamp, an RSSI, a hop count and a
   message id to a CSV you can export.
3. Set every device to the same screen brightness and turn off battery saver,
   adaptive battery and any aggressive app-killer. On Android also exclude
   both apps from Doze if the OS lets you. This is the single most common way
   these campaigns produce garbage.
4. Charge every device to 100 %. Record the exact battery percentage per
   device at the start of every round.
5. Sync the clocks. Everything downstream depends on timestamps being
   comparable, and without a network they will drift. Before each session,
   bring all devices together and run the harness's clock-sync step, which
   records each device's offset against one nominated reference device.
6. Label the devices physically. `D1` through `D5`, written on tape, on the
   back. You will lose track otherwise, and a mislabelled device silently
   corrupts a whole round.

## The site

One street in a built-up area, with buildings on both sides. The same street
for every round, so results are comparable. Note it down: street name,
approximate building height, whether it is one of a dense grid or an open
road, and the weather. Avoid an open park, which flatters every link and
measures nothing anyone will experience.

Measure your distances once, properly, and mark them. Pace them out or use a
measuring app, put something you can see at each mark, and reuse the same
marks all day. Distance error is the dominant error in M1 and it is entirely
avoidable.

## Round A — per-hop distance (metric M1)

Two people, one device each. For each distance band in order — 10, 20, 30, 50,
75, 100, 150 m — and for each app:

1. Stand at the marks. Both devices in a trouser pocket, screen off, app
   backgrounded. **This is the condition that matters.** A number taken with
   two phones held up in front of two faces is not the number.
2. Send 30 messages, one every 10 seconds, from one device to the other.
3. Record, per message: sent at, received at or not received, and the RSSI
   the receiver logged.
4. Repeat with the roles reversed. Asymmetry is real and worth knowing about.
5. Repeat the whole band with both devices held in hand, screen on, app in
   foreground. That gives you the foreground/background delta, which is the
   number that tells us how much of the problem is the operating system
   rather than the radio.

Do this for all three platform pairs: iOS-iOS, Android-Android, iOS-Android.
The mixed pair is the one that matters most and the one nobody publishes.

Alternate the apps band by band rather than doing all of Bridgefy then all of
ours — conditions drift over an hour, and alternating means the drift hits
both equally instead of becoming a fake advantage for whichever went second.

Stop increasing distance after two consecutive bands at zero delivery for both
apps.

## Round B — multi-hop delivery, static chain (metric M2)

Four or five people, one device each, in a line along the street, spaced at
**60 % of the median one-hop distance you measured in Round A**. That spacing
is the point: it must be close enough that each neighbour pair links reliably
and far enough that no non-adjacent pair can hear each other. Verify that
before you start — walk the ends apart and confirm D1 cannot see D3 directly.
If it can, spread out. A chain where D1 reaches D4 directly is not measuring
3 hops and is the most common way this round goes wrong.

All devices pocketed, screens off, apps backgrounded.

1. Send 50 messages from D1, one every 15 seconds.
2. Record at D4 (3 hops) and D5 (4 hops): which ids arrived, and when.
3. Record at every intermediate device too: which ids it saw and how many
   times it saw each. That gives us redundant receptions per delivery, which
   is how we show the flood-efficiency difference.
4. Repeat for the other app.
5. If you have a fifth device, run one round with it as a 5-hop extension and
   one with it parked as an observer beside D1, logging everything it hears.
   The observer round is how we measure transmissions per delivered message
   without instrumenting every node.

Note the platform of every position in the chain. A chain with an iPhone in
the middle, backgrounded, is a different experiment from one with an Android
there, and the difference is something we expect to be large.

## Round C — carrier regime (the other half of M2)

This is the round that tests the product's central claim, and no competitor
publishes anything like it.

1. Put two clusters of two devices at opposite ends of a block, far enough
   apart that nothing links them. Confirm no delivery with a test message.
2. Send 20 messages from a device in cluster 1. They must all fail to arrive.
3. Now one person walks from cluster 1 to cluster 2 at a normal pace, carrying
   a fifth device that is a member of the channel. Note the time they leave
   and the time they arrive.
4. Record what arrives at cluster 2, and when, relative to the carrier's
   arrival.
5. Repeat for the other app. Bridgefy may deliver little or nothing here; that
   is itself the result, and it should be reported plainly rather than
   dressed up.

Run this twice: once where the carrier pauses in each cluster for 60 seconds,
and once where they walk straight through without stopping. The
walk-straight-through case is the hard one and the realistic one.

## Round D — battery

1. Full charge, note the percentage.
2. All devices pocketed, screens off, app backgrounded, idle in a channel with
   one other device in range. No messages.
3. Leave for two hours. Note the percentage every 30 minutes.
4. Compute %/hr. Note the device model and its battery capacity in mAh, and
   whether the battery is old — a two-year-old phone's figure is not
   comparable to a new one's and we need to know which we have.

This is the only battery measurement the project will have. Everything else is
modelled, so this one round decides whether our 5 %/hr claim is real.

## What to send back

Export the CSVs from each device and send them with a note giving, per round:
the site, the weather, the device at each position with its platform and OS
version, the app versions, the start and end battery per device, and anything
that went wrong. **Especially anything that went wrong.** A round where a
phone's screen woke up in a pocket, or someone stood in the wrong place, or an
OS killed an app, is still useful if we know about it and worthless if we do
not.

The simulator is refitted against these numbers and every figure derived from
it afterwards cites the round it rests on. Until the first set arrives, every
performance claim in this project is modelled, and the progress page says so.
