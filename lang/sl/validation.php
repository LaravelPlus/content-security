<?php

declare(strict_types=1);

return [
    'rejected_file' => 'Ta datoteka ni prestala varnostnega preverjanja.',
    'rejected_text' => 'To besedilo ni prestalo varnostnega preverjanja.',
    'rejected_content' => 'Ta vsebina ni prestala varnostnega preverjanja.',

    'failed_file' => 'Varnostnega preverjanja datoteke ni bilo mogoče dokončati. Poskusite znova.',
    'failed_text' => 'Varnostnega preverjanja besedila ni bilo mogoče dokončati. Poskusite znova.',
    'failed_content' => 'Varnostnega preverjanja vsebine ni bilo mogoče dokončati. Poskusite znova.',

    'upload_failed' => 'Nalaganje se ni dokončalo. Poskusite znova.',

    // Size and count limits are not probes: telling the user the limit is
    // what lets them fix the upload.
    'too_large' => 'Datoteka je prevelika. Največja dovoljena velikost je :max.',
    'too_many_files' => 'Preveč datotek. Največ jih je lahko :max.',
    'batch_too_large' => 'Datoteke so skupaj prevelike. Največja dovoljena skupna velikost je :max.',
    'malware_detected' => 'Ta datoteka ni prestala varnostnega preverjanja.',

    'url_invalid' => 'To ni videti kot veljaven spletni naslov.',
    'url_scheme' => 'Sprejemamo samo naslove http:// in https://.',
    'url_credentials' => 'Spletni naslovi z uporabniškim imenom ali geslom niso sprejeti.',
    'url_internal' => 'Ta naslov kaže na interni cilj in ga ni mogoče uporabiti.',
    'url_unicode' => 'Ta spletni naslov uporablja znake, ki lahko posnemajo drugo domeno.',
];
