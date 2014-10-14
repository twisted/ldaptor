An objectclass example
======================

|   objectclass ( 2.5.6.6 NAME 'person'
|       DESC 'RFC2256: a person'
|       SUP top STRUCTURAL
|       MUST ( sn $ cn )
|       MAY ( userPassword $ telephoneNumber $ seeAlso $ description )
|   )
