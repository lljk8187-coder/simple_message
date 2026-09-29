"""通道适配器登记表。

适配器子类用 @register 装饰（或 register(cls) 调用）登记自己；
内核与前端永远通过 registry.get(platform) 取适配器，不感知具体平台。

load_adapters() 在 hub 启动时调用：逐个导入适配器模块触发注册，
缺失的模块（可选依赖未装、或尚未实现）静默跳过——平台列表因此自动伸缩。
"""

ADAPTERS = {}

# 适配器模块清单（app/platform/ 下）。新平台：加文件 + 在此追加一行。
_MODULES = ('tiktok', 'x', 'instagram', 'facebook', 'email')


def register(cls):
    """类装饰器：把适配器类按其 platform 标识登记。"""
    if not getattr(cls, 'platform', ''):
        raise ValueError('adapter %r has no platform id' % cls)
    ADAPTERS[cls.platform] = cls
    return cls


def get(platform):
    """取平台适配器类；未注册的平台抛 KeyError（调用方转成用户可读错误）。"""
    return ADAPTERS[platform]


def all_adapters():
    """全部已登记适配器：{platform: cls}。"""
    return dict(ADAPTERS)


def load_adapters():
    """导入全部适配器模块触发注册。

    只吞掉"模块文件不存在"的 ModuleNotFoundError（过渡期/可选平台）；
    模块内部的错误（语法、依赖缺失外的异常）照常抛出——适配器自己的
    可选依赖应在方法内惰性导入，而不是在模块顶层。
    """
    import importlib
    for name in _MODULES:
        try:
            importlib.import_module('.' + name, __package__)
        except ModuleNotFoundError as e:
            # 仅当缺失的是适配器模块本身时跳过；其内部依赖缺失照常抛出
            if ('.' + name) in str(e) or name in str(e).split():
                continue
            raise
