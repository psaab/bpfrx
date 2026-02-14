project('dpdk_worker', 'c',
    version: '0.1',
    default_options: ['c_std=c11', 'warning_level=2'])

dpdk = dependency('libdpdk', required: true)

sources = files(
    'main.c',
    'pipeline.c',
    'parse.c',
    'screen.c',
    'zone.c',
    'conntrack.c',
    'policy.c',
    'nat.c',
    'nat64.c',
    'forward.c',
    'filter.c',
    'reject.c',
    'gc.c',
    'rx_poll.c',
    'rx_interrupt.c',
    'rx_adaptive.c',
    'power.c',
)

executable('dpdk_worker', sources, dependencies: dpdk)
