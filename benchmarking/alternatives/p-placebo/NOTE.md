Work through the repository the way a careful reviewer would. Start by getting oriented: list the
directories, find the entry points and the configuration, and read the files that look central
before you read the ones that look peripheral. Keep a running picture of how data moves through the
program, where it comes from, how it is changed, and where it ends up.

Read code in the order a request or a job would travel through it. When a function calls another
function, follow the call and read the callee rather than assuming what it does from its name.
Names are a useful hint and an unreliable guarantee. Where two pieces of code look alike, compare
them line by line, because small differences between near-duplicates are often meaningful.

Be systematic about coverage. Say to yourself which parts of the repository you have read and which
you have not, and do not let a long file or an interesting early discovery pull your attention away
from the rest. A review that stops at the first thing it notices tends to miss the second and third.
Return to files you skimmed once you understand the program better, because early reading is done
with less context than later reading.

Be precise in what you report. For every candidate, state the file and line, say exactly what is
supplied from outside and by whom, say what operation or resource is affected, and describe the path
between the two with line references. If you cannot describe the path, keep reading until you can or
drop the candidate. Prefer a smaller set of well-supported findings over a long list of guesses, but
do not discard a candidate only because it looks unusual.

When you are unsure, look for evidence in the code rather than reasoning from convention. Check the
tests, the documentation strings, the call sites and the configuration to see how a piece of code is
meant to be used. Note anything that contradicts your first reading and revise it. If the evidence
points both ways, say so in the finding.

Write down your reasoning in plain language as you go, so that each conclusion can be traced to the
lines that support it. Take your time. Thoroughness matters more than speed, and a calm, methodical
pass over the whole repository is more useful than a quick pass over part of it. When you have read
everything that matters, look back over your notes once more for anything you set aside, then
produce your final report.

Different programs are organised in different ways, and the same idea can look quite different in
different languages and frameworks. Do not assume that a repository follows the conventions you know
best. Learn how this one is laid out, how its authors name things, and how they usually handle
errors, and read the code against those local habits. Where a file departs from the pattern used
everywhere else, it is worth a closer look, because departures are where mistakes tend to hide.

Finally, keep your report organised. Group related observations, avoid repeating yourself, and make
each entry stand on its own so that a reader who has not seen the code can follow it. If something
you looked at turned out to be fine, you do not need to mention it unless it explains why a
candidate was dropped.
