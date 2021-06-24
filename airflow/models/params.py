import attr
from attr.validators import in_, instance_of, optional
from typing import TYPE_CHECKING, Any, List, Dict, Iterable, Union, Optional
import re


@attr.s(auto_attribs=True)
class BaseParam:
    required: Optional[bool] = attr.ib(default=False, validator=instance_of(bool))


@attr.s(auto_attribs=True)
class BoolParam(BaseParam):
    default: Optional[Union[bool, None]] = attr.ib(default=None, validator=optional(instance_of(bool)))

    def __call__(self) -> bool:
        if self.required and self.default is None:
            raise ValueError(f'value is required but not provided')
        return self.default


@attr.s(auto_attribs=True)
class IntParam(BaseParam):
    default: Optional[Union[int, None]] = attr.ib(default=None, validator=optional(instance_of(int)))
    min: Optional[Union[int, None]] = attr.ib(default=None, validator=optional(instance_of(int)))
    max: Optional[Union[int, None]] = attr.ib(default=None, validator=optional(instance_of(int)))

    def __attrs_post_init__(self):
        if self.default and self.min and self.min > self.default:
            raise ValueError(f"value can not be less than the minimum allowed value: {self.min}")
        if self.default and self.max and self.max < self.default:
            raise ValueError(f'value can not be greater than the maximum allowed value: {self.max}')
        if self.min and self.max and self.min > self.max:
            raise ValueError(f'min value can not be more than the max value')

    def __call__(self) -> int:
        if self.required and self.default is None:
            raise ValueError(f'value is required but not provided')
        # run the validations
        self.__attrs_post_init__()
        return self.default


@attr.s(auto_attribs=True)
class FloatParam(BaseParam):
    default: Optional[Union[float, None]] = attr.ib(default=None, validator=optional(instance_of(float)))
    min: Optional[Union[float, None]] = attr.ib(default=None, validator=optional(instance_of(float)))
    max: Optional[Union[float, None]] = attr.ib(default=None, validator=optional(instance_of(float)))

    def __attrs_post_init__(self):
        if self.default and self.min and self.min > self.default:
            raise ValueError(f"value can not be less than the minimum allowed value: {self.min}")
        if self.default and self.max and self.max < self.default:
            raise ValueError(f'value can not be greater than the maximum allowed value: {self.max}')
        if self.min and self.max and self.min > self.max:
            raise ValueError(f'min value can not be more than the max value')

    def __call__(self) -> float:
        if self.required and self.default is None:
            raise ValueError(f'value is required but not provided')
        # run the validations
        self.__attrs_post_init__()
        return self.default


@attr.s(auto_attribs=True)
class StringParam(BaseParam):
    default: Optional[Union[str, None]] = attr.ib(default=None, validator=optional(instance_of(str)))
    option_list: Optional[Union[List, None]] = attr.ib(default=None, validator=optional(instance_of(List)))
    match_regex: Optional[Union[int, None]] = attr.ib(default=None, validator=optional(instance_of(str)))

    def __attrs_post_init__(self):
        if self.default and self.option_list and self.default not in self.option_list:
            raise ValueError(f"value is not part of option list: '{self.option_list}'")
        if self.default and self.match_regex and not re.compile(self.match_regex).match(self.default):
            raise ValueError(f'value does not match with the regex: {self.match_regex}')
        if self.match_regex and self.option_list:
            raise ValueError(f'option_list and match_regex can not be applied together')

    def __call__(self) -> str:
        if self.required and self.default is None:
            raise ValueError(f'value is required but not provided')
        # run the validations
        self.__attrs_post_init__()
        return self.default


@attr.s(auto_attribs=True)
class ListParam(BaseParam):
    default: Optional[Union[list, None]] = attr.ib(default=None, validator=optional(instance_of(list)))

    def __call__(self) -> list:
        for idx, item in enumerate(self.default):
            if isinstance(item, BaseParam):
                self.default[idx] = item()

        return self.default


@attr.s(auto_attribs=True)
class DictParam(BaseParam):
    default: Optional[Union[dict, None]] = attr.ib(default=None, validator=optional(instance_of(dict)))

    def __call__(self) -> dict:
        for k, v in self.default.items():
            if isinstance(v, BaseParam):
                self.default[k] = v()

        return self.default


PARAMS_TYPE_MAP = {
    bool: BoolParam,
    int: IntParam,
    float: FloatParam,
    str: StringParam,
    list: ListParam,
    dict: DictParam,
}


if __name__ == '__main__':
    i = IntParam(min=1, max=10)
    i.default = 2
    print(i())

    j = StringParam(default='test', required=False, option_list=['abc', 'test'])
    print(j())

    b = BoolParam(default=None, required=False)
    print(b())

    f = FloatParam(default=1.0, min=0.0, max=100.0)
    print(f())

    g = BaseParam.new(param_type=int, default=10, min=0, max=20)
    print(g())

    l = ListParam(default=[j, b, f])
    print(l())

    d = DictParam(default={'str': j, 'bool': "efesdad", 'flt': f})
    print(d())
