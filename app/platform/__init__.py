"""平台适配层 —— 见 base.py 的统一模型与通道契约说明。"""


def load_adapters():
    """导入全部适配器模块触发注册（详见 registry.py）。"""
    from . import registry
    registry.load_adapters()
