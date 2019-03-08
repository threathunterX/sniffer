#!/usr/bin/env python
# -*- coding: utf-8 -*-


import requests
import logging

from threathunter_common.util import millis_now

# url折叠标记
FOLD_FLAG = '****'

logger = logging.getLogger('bones')


class URLTreeNode(object):
    """
    URL Tree的关键节点，对应到url路径中的每个部分

    一个树节点分三部分：
                      ___________
                     |  url part |
                     |___________|
          _________________|________________
       __|__     __|__          __|__     __|__
      |  N1 |   |  N2 |        |  O1 |   |  O2 |
      |_____|   |_____|        |_____|   |_____|
    1. 首先是节点自身，有一个部分url内容，形如www.host.com/path1/path2, 像'www.host.com', 'path1', 'path2'分别是三个节点
    2. 由O1,O2.....组成的普通子节点，表示这个url节点的后续部分，当这些儿子节点数量过多时，会触发折叠
    3. 由N1,N2.....组成的命名节点，这些节点来自于手工的配置，比如我们配置了www.threathunter.cn/shops/order, 则这个url包含的三个节点都是
       命名节点，这些节点因为在人工配置里面出现，可能会与自动折叠冲突，所以单独列出，本身不允许加入到折叠的逻辑中去，这点比较特殊

    """

    def __init__(self, depth, value, parent, is_leaf, disable_fold):
        """
        新建一个node
        :param depth: 节点的高度，root为空，高度0；host在高度1; 往下依次递增
        :param value: 该节点的值，url的一部分或者是表示fold的内容(FOLD_FLAG)
        :param parent: 父节点
        :param is_leaf: 是否可以作为一个叶子节点，表示可以作为一个url。is_leaf只是逻辑概念，由于url可以有共同前缀，所以逻辑上的leaf
                        节点下可能还有节点（对应到别的url）
        :param disable_fold: 该节点下禁止折叠
        """

        self.depth = depth
        self.value = value
        self.parent = parent
        self.is_leaf = is_leaf
        self.disable_fold = disable_fold

        # max_children: 最多有多少个子节点, 超过就开始折叠
        from complexconfig.configcontainer import configcontainer
        sniffer_config = configcontainer.get_config("sniffer")
        if self.depth == 0:
            # as many hosts
            self.max_children = 1000000
        elif self.depth <= 2:
            self.max_children = sniffer_config.get_int('sniffer.urltree.rootnodes.width', 300)
        else:
            self.max_children = sniffer_config.get_int('sniffer.urltree.leafnodes.width', 30)

        # 本节点下的普通节点是否折叠
        self.is_fold = False
        # 表示折叠是否是因为配置造成的
        self.fold_by_config = False
        # 表示折叠是否是因为子节点过多
        self.fold_by_too_many_children = False
        # children有两种，ordinary_children表示普通的子节点，数量超过可以折叠掉；nominated_children表示通过配置得到的节点，
        # 不允许折叠
        self.ordinary_children = dict()
        self.nominated_children = dict()
        # 访问计数
        self.visit_count = 0

    def fold(self, fold_by_config, force=False):
        """
        尝试对本节点进行折叠

        :param fold_by_config: True表示配置导致，强制折叠, 这时不考虑ordinary_children的数量; 否则表示尝试自动折叠，当前
                               ordinary_children的数量要去和max_children做比较, 超过才能折叠
        :param force: force=True表示不考虑max_children
        :return: 是否做了折叠
        """

        if self.disable_fold:
            return False

        # 本身有可能已经折叠，但人工配置的表意更高，覆盖一下
        if fold_by_config:
            self.fold_by_config = fold_by_config

        if self.is_fold:
            if len(self.ordinary_children) <= 1:
                # 已经折叠，不需要继续下去了
                return True
            else:
                # 有可能折叠状态，合并进来其他节点，所以再次合并一下
                pass

        if not fold_by_config:
            if not force and len(self.ordinary_children) <= self.max_children:
                return False
            else:
                self.fold_by_too_many_children = True

        # 先强行合并，再设置fold标记
        # 合并只针对ordinary_children
        if self.ordinary_children:
            fold_node = merge_ordinary_nodes_due_to_fold(list(self.ordinary_children.values()))
        else:
            # 没有就新建一个
            fold_node = URLTreeNode(self.depth + 1, FOLD_FLAG, self, False, False)

        fold_node.parent = self

        # 更新折叠状态
        self.is_fold = True
        self.fold_by_config = fold_by_config
        self.ordinary_children = {fold_node.value: fold_node}
        return True

    def get_exact_child(self, value):
        """
        严格返回匹配的child
        :param value: url节点值
        :return:
        """

        return self.ordinary_children.get(value) or self.nominated_children.get(value)

    def _get_child(self, value, is_ordinary):
        """
        通过url内容来找到相应的子节点。

        :param value: url内容
        :param is_ordinary: 是否普通节点
        :return: 对应到value的节点，如果找不到返回None
        """

        if is_ordinary:
            if self.is_fold:
                return list(self.ordinary_children.values())[0]
            else:
                return self.ordinary_children.get(value)
        else:
            return self.nominated_children.get(value)

    def _add_child(self, child, is_ordinary):
        """
        增加，之前已经确认没有该child了
        assert self.get_child(child.value, is_ordinary) is None

        :param child: 需要增加的节点
        :param is_ordinary: 是否普通节点
        """

        child_value = child.value
        child.parent = self  # assure again
        if is_ordinary:
            if self.is_fold:
                pass  # fold node should already have a FOLD_FLAG node
            else:
                self.ordinary_children[child_value] = child
                # 可能需要fold
                self.fold(False)
        else:
            self.nominated_children[child_value] = child

    def assure_child_during_automation(self, value):
        """
        作自动化处理时，获取树中的一个节点，没有就新增。

        自动化处理，数据来源包括两种：1. 自身获取的url数据； 2. 从server中拿到的url折叠信息，这个是由自己或其他节点定期上报的自动化数据
        新增节点时，新增在普通子节点列表中就可以

        :param value: url内容
        :return: 已有或者新增的节点
        """

        # 先从两种现有的子节点列表中查找
        result = self._get_child(value, False) or self._get_child(value, True)
        if result:
            return result

        # 增加一个普通节点
        child_node = URLTreeNode(self.depth + 1, value, self, False, False)
        self._add_child(child_node, True)
        # 可能触发折叠，需要重新获取, 这次肯定有了
        result = self._get_child(value, True)
        return result

    def assure_child_during_config(self, value):
        """
        对于人工配置的url，找到一个节点，没有就新增
        新增节点时，新增在nominated子节点列表中

        :param value: url内容
        :return: 已有或者新增的节点
        """

        # 1. 恰巧表示fold, 强制折叠
        if value == FOLD_FLAG:
            if not self.fold(True):
                # 1.1 折叠失败，异常，此规则失效
                return None
            else:
                # 折叠成功，则去普通节点就好了
                return self._get_child(value, True)

        # 2. 已经在命名节点中, 直接返回
        result = self._get_child(value, False)
        if result:
            return result

        # 3. 居然在普通节点中并且不是折叠，把他调过来吧
        # 补充说明，现在同步改为所有配置先生成树，这里就不存在可能为普通节点的情况，因为生成时，先人工配置，在自动配置，所以普通节点出现在
        # 后面
        result = self._get_child(value, True)
        if result and result.value != FOLD_FLAG:
            del self.ordinary_children[value]
            self.nominated_children[value] = result
            return result

        # 4. 都找不到，增加一个命名节点
        child_node = URLTreeNode(self.depth + 1, value, self, False, False)
        self._add_child(child_node, False)
        result = self._get_child(value, False)
        return result

    def mark_leaf(self):
        """
        强制设置自己表示一个逻辑上的叶子节点，即自己可能是一个url

        :return:
        """
        self.is_leaf = True
        self.visit_count += 1

    def unfold(self):
        """
        这个节点下禁止fold
        :return:
        """
        if not self.is_fold:
            return
        else:
            # 恢复折叠的逻辑, 把下面的折叠node丢弃掉，这里会丢掉所有的子树，因为没有足够的信息去还原了
            self.ordinary_children = dict()
            self.is_fold = False
            self.fold_by_config = False
            self.fold_by_too_many_children = False
            self.visit_count = 0

    def get_all_children_list(self):
        """
        获取所有子节点的合集，并按顺序排好, 普通节点在前，unfold节点在后
        :return: children sorted by node value
        """

        ordinary_items = self.ordinary_children.items()
        ordinary_items.sort(key=lambda x: x[0])
        ordinary_items = [_[1] for _ in ordinary_items]

        unfold_items = self.nominated_children.items()
        unfold_items.sort(key=lambda x: x[0])
        unfold_items = [_[1] for _ in unfold_items]
        return ordinary_items + unfold_items

    def get_all_url_under_this_node(self, prefix, result_list):
        """
        获取以自己为root下面的子树的所有的url

        :param prefix: 之前的前缀
        :param result_list: 结果全部放到result，这个参数有副作用
        """

        if prefix:
            prefix = prefix + '/' + self.value
        else:
            prefix = self.value

        if self.is_leaf:
            result_list.append(prefix)

        for child in self.get_all_children_list():
            child.get_all_url_under_this_node(prefix, result_list)

    def get_all_leaves_under_this_node(self, prefix, result_dict):
        """
        获取以自己为root下面的子树的所有的叶子节点，并且返回每个叶子节点的访问数，存储在result_dict里面

        :param prefix: 之前的前缀
        :param result_list: 结果全部放到result_dict，这个参数有副作用
        """

        if prefix:
            prefix = prefix + '/' + self.value
        else:
            prefix = self.value

        if self.is_leaf:
            result_dict[prefix] = self.visit_count

        for child in self.get_all_children_list():
            child.get_all_leaves_under_this_node(prefix, result_dict)

    def clean_visit_count(self):
        """
        将自己为root下面的子树的所有节点的visit_count清零
        """

        self.visit_count = 0

        for child in self.get_all_children_list():
            child.clean_visit_count()

    def get_all_generated_fold_url(self, prefix, result_list):
        """
        获取以自己为root下面的子树的所有自动生成的fold规则

        :param prefix: 之前的前缀
        :param result_list: 结果全部放到result，这个参数有副作用
        """

        if prefix:
            prefix = prefix + '/' + self.value
        else:
            prefix = self.value

        if self.value == FOLD_FLAG and (self.parent and self.parent.fold_by_too_many_children):
            # 自身是一个折叠标示节点，同时父节点也标示了自动折叠
            result_list.append(prefix)

        for child in self.get_all_children_list():
            child.get_all_generated_fold_url(prefix, result_list)

    def get_all_fold_url(self, prefix, result_list):
        """
        获取所有的折叠规则

        :param prefix: 之前的前缀
        :param result_list: 结果全部放到result，这个参数有副作用
        """

        if prefix:
            prefix = prefix + '/' + self.value
        else:
            prefix = self.value

        if self.value == FOLD_FLAG:
            # 自身是一个折叠标示节点，同时父节点也标示了自动折叠
            result_list.append(prefix)

        for child in self.get_all_children_list():
            child.get_all_fold_url(prefix, result_list)

    def get_nodes_under_me(self):
        """
        获取此节点下方（包括自身）的所有节点数量
        :return: 节点数量
        """
        result = 1
        for child in self.get_all_children_list():
            result += child.get_nodes_under_me()
        return result

    def get_subtree_string(self, print_prefix, smallest_child, nominated):
        """
        打印当前子树
        :param print_prefix: 打印的前缀, 例如'|  |  |'这种
        :param smallest_child: 是否是兄弟节点中的最后一个
        :param nominated: 是否是命名节点
        :return:
        """

        result = ''

        # 1. 首先打印当前节点
        self_print_value = '{}{}{}{}'.format('*' if nominated else '', self.value, '$' if self.is_leaf else '',
                                             '<' if self.disable_fold else '')
        if self.visit_count > 0:
            self_print_value = self_print_value + '({})'.format(self.visit_count)
        result += '{}|__{}\n'.format(print_prefix, self_print_value)

        # 2. 打印子节点
        if smallest_child:
            subnode_prefix = print_prefix + ' ' + ' ' * (2 + len(self_print_value))
        else:
            subnode_prefix = print_prefix + '|' + ' ' * (2 + len(self_print_value))

        children = self.get_all_children_list()
        for index, child in enumerate(children):
            # 加一下间隔
            result += subnode_prefix + '|' + '\n'
            result += child.get_subtree_string(subnode_prefix, index == len(children) - 1,
                                               child.value in self.nominated_children)

        return result

    def merge_ordinary_nodes_when_fold(self, nodes_list):
        """
        当处于折叠状态时，合并其他节点进来
        :return:
        """
        if not self.is_fold:
            return

        # 先拿到自己下面已有的那个折叠节点
        fold_node = list(self.ordinary_children.values())[0]
        # 跟新的节点合并生成新的折叠节点
        new_fold_node = merge_ordinary_nodes_due_to_fold([fold_node] + nodes_list)
        self.ordinary_children[FOLD_FLAG] = new_fold_node

    def cancel_all_the_config_status_under_me(self):
        """
        在当前节点下的子树中，取消掉所有手工配置带来的影响。

        当发现手工配置中已经撤销了某个节点下的所有配置，则会触发此操作
        :return:
        """

        # 1. 取消禁止折叠
        if self.disable_fold:
            self.disable_fold = False
            self.fold(False)

        # 2. 取消配置带来的折叠
        if self.fold_by_config and not self.fold_by_too_many_children:
            self.unfold()

        # 3. 取消命名节点, 搬到普通节点中去
        if self.nominated_children:
            if self.is_fold:
                # 3.1 依然是fold状态，则把命名节点合并进来
                self.merge_ordinary_nodes_when_fold(self.nominated_children.values())
            else:
                # 3.2, 两边不会冲突，简单合并，并尝试折叠
                self.ordinary_children.update(self.nominated_children)
                self.fold(False)

            self.nominated_children = {}

        # 4. 对所有的普通子节点，循环调用
        for child in self.ordinary_children.values():
            child.cancel_all_the_config_status_under_me()


def _merge_nodes_with_same_value(nodes_list):
    """
    对所有value相同的节点进行合并。

    :param nodes_list: 所有节点value都一样
    :return: 一个单独的节点
    """

    assert nodes_list, 'nodes should not be empty'

    if len(nodes_list) == 1:
        # no need for merge
        return nodes_list[0]

    # 把所有节点的norminated节点和普通节点进行合并
    all_nominated_children_nodes = dict()
    all_ordinary_children_nodes = dict()
    for node in nodes_list:
        for child_value, child in node.nominated_children.iteritems():
            all_nominated_children_nodes.setdefault(child_value, set()).add(child)
        for child_value, child in node.ordinary_children.iteritems():
            all_ordinary_children_nodes.setdefault(child_value, set()).add(child)

    new_ordinary_children = dict()
    for child_value, child_nodes in all_ordinary_children_nodes.iteritems():
        child_nodes = list(child_nodes)
        if len(child_nodes) == 1:
            new_ordinary_children[child_value] = child_nodes[0]
        else:
            new_ordinary_children[child_value] = merge_ordinary_nodes_due_to_same_name(child_nodes)
    new_nominated_children = dict()

    # 命名节点的祖先应该只有命名节点或者折叠节点，所以不会触发下面的逻辑
    for child_value, child_nodes in all_nominated_children_nodes.iteritems():
        child_nodes = list(child_nodes)
        if len(child_nodes) == 1:
            new_nominated_children[child_value] = child_nodes[0]
        else:
            new_nominated_children[child_value] = merge_nominated_nodes(child_nodes)

    # 1. 在此情况下，depth, parent, value, max_children取第一个节点的值即可
    #    命名节点合并为命名节点，普通节点合并为新的普通节点, 所以nominated值也不变化
    return_node = nodes_list[0]

    # 2. children更新
    return_node.ordinary_children = new_ordinary_children
    return_node.nominated_children = new_nominated_children

    # 3. is_leaf, disable_fold，被合并的节点只要有一个是，就全是
    return_node.is_leaf = any(node.is_leaf for node in nodes_list)
    return_node.disable_fold = any(node.disable_fold for node in nodes_list)
    return_node.visit_count = sum(node.visit_count for node in nodes_list)

    # 4. 看fold逻辑，这里比较复杂
    one_node_ever_fold = any(node.is_fold for node in nodes_list)

    if return_node.disable_fold:
        # 4.1 合并的节点中，有的节点标明禁止折叠，有的已经折叠。禁止折叠优先级更高
        # 补充说明：disable_fold说明是手工配置的节点，应该是命名节点，应该不会触发到此逻辑
        return_node.is_fold = False
        return_node.fold_by_config = False
        return_node.fold_by_too_many_children = False
        if FOLD_FLAG in return_node.ordinary_children:
            # 这种情况就是4.1的情况，把合并节点去掉
            del return_node.ordinary_children[FOLD_FLAG]
    else:
        if not one_node_ever_fold:
            # 4.2 被合并的节点自己都没有合并过
            return_node.is_fold = False
            return_node.fold_by_config = False
            return_node.fold_by_too_many_children = False
            # 因为有合并，再次尝试一下自动合并
            return_node.fold(False)
        else:
            # 4.3 有一个节点已经合并过，那么我们自己也应该合并
            fold_by_too_many_children = any(node.fold_by_too_many_children for node in nodes_list)
            fold_by_config = any(node.fold_by_config for node in nodes_list)
            if fold_by_too_many_children:
                # 4.3.1 表示是曾经由于自动折叠过，也要强制折叠
                return_node.fold(False, True)
            if fold_by_config:
                # 4.3.2 表示是由于配置折叠的，强制折叠
                return_node.fold(True)

    return return_node


def merge_ordinary_nodes_due_to_same_name(nodes_list):
    """
    合并普通节点，只是因为重名
    """
    result = _merge_nodes_with_same_value(nodes_list)
    return result


def merge_ordinary_nodes_due_to_fold(nodes_list):
    """
    合并普通节点，由于折叠，所以生成的节点会改名
    """
    result = _merge_nodes_with_same_value(nodes_list)
    result.value = FOLD_FLAG
    return result


def merge_nominated_nodes(nodes_list):
    """
    合并命名节点.

    命名节点的祖先一定是命名节点或者已经是折叠节点，所以这一步不需要
    :param nodes_list:
    :return:
    """

    result = _merge_nodes_with_same_value(nodes_list)
    return result


def sync_with_new_config_node(raw_node, config_node):
    """
    当配置发生变化时，我们希望将当前的url树和配置产生的树进行合并，这个合并是每个节点递归进行的。
    raw_node表示当前工作的树中的一个节点，config_node是配置生成的树中的一个节点，大家的位置是一样的，raw_node，会把config_node中的
    信息同步过来.

    """

    # 同步当前有效的树和新的配置树，为了保证状态能准确同步，逻辑非常复杂。将会按照以下的顺序进行
    # 首先同步disable_fold状态，这个是同步手工配置的黑名单
    # 接着同步fold_by_config状态，这个是配置手工配置的白名单以及从服务器同步过来的生成白名单
    # 然后同步命名子节点
    # 接着是同步普通子节点, 这里又分两步，先处理折叠状态，再进行合并

    # 1. 先看本身的内容, 先做disable_fold的配置比较
    if raw_node.disable_fold:
        if config_node.disable_fold:
            # 1.1 两边都是禁止折叠，不冲突
            pass
        else:
            # 1.2 说明配置发生了变更，以前禁止折叠，现在取消了, 更正过来
            raw_node.disable_fold = False
            # 弥补一下做次fold
            raw_node.fold(False)
    else:
        if not config_node.disable_fold:
            # 1.3 两边都一样
            pass
        else:
            # 1.4 增加了禁止折叠
            raw_node.disable_fold = True
            # 尝试取消折叠
            raw_node.unfold()

    # 2. 在看看fold_by_config的同步
    if raw_node.fold_by_config:
        if not config_node.fold_by_config:
            # 2.1 以前认为要折叠，现在取消了
            raw_node.fold_by_config = False
            if not raw_node.fold_by_too_many_children:
                # 2.1.1 也没有因为子节点过多折叠过，那么取消折叠
                raw_node.unfold()
            else:
                # 2.1.2 本身就会触发折叠，不管它
                pass
        else:
            # 2.2 两边配置都认为要折叠，所以没变化
            pass
    else:
        if not config_node.fold_by_config:
            # 2.3 两边配置认为都不要折叠，没有变化
            pass
        else:
            # 2.4 新配置要求折叠, 先对现有节点强制折叠
            if raw_node.fold_by_too_many_children:
                # 2.4.1 已经自动折叠过，更新一下状态
                raw_node.fold_by_config = True
            else:
                # 2.4.2 强制折叠一下
                raw_node.fold(True)

    # 3. 先同步nominated child
    for nominated_value, nominated_child in raw_node.nominated_children.items():
        if nominated_value in config_node.nominated_children:
            # 3.1 有个子节点同时出现在两边的命名节点中，过会递归处理他们
            pass
        else:
            # 3.2 有个子节点只出现当前树的命名节点中，不在config中，说明配置里面做了删除，把此节点清除配置信息后挪到普通节点中去
            del raw_node.nominated_children[nominated_value]
            nominated_child.cancel_all_the_config_status_under_me()

            if not raw_node.is_fold:
                # 3.2.1 raw_node尚未折叠, 那么直接放进去, 这里不会有冲突
                raw_node.ordinary_children[nominated_value] = nominated_child
                # 新增一个节点，尝试fold
                raw_node.fold(False)
            else:
                # 3.2.2 raw_node已经折叠, 则将此节点和折叠的节点进行merge
                raw_node.merge_ordinary_nodes_when_fold([nominated_child])
                # is_fold等状态保持原样

    for nominated_value, nominated_child in config_node.nominated_children.iteritems():
        if nominated_value in raw_node.nominated_children:
            # 情况3.1， 已经处理
            pass
        else:
            # 3.3, 配置新增的节点, 原来的命名节点中没有, 所以是配置新增
            if nominated_value in raw_node.ordinary_children:
                # 3.3.1 曾经出现在普通节点列表里面，这里nominated_value肯定是一个特定的值，而且也没折叠，先搬到命名节点列表里面去
                existing_node = raw_node.ordinary_children[nominated_value]
                del raw_node.ordinary_children[nominated_value]
                # 搬迁
                raw_node.nominated_children[nominated_value] = existing_node
                # 过会再和配置合并
            else:
                # 3.3.2 普通节点列表里面，也没有，完全新增，先生成一个节点，待会合并
                raw_node.assure_child_during_config(nominated_value)

    # 现在命名节点列表好了，递归同步他们
    for nominated_value, nominated_child in config_node.nominated_children.items():
        raw_nominated_child = raw_node.nominated_children.get(nominated_value)
        # 两边同步过，现在是肯定两边同时存在的
        sync_with_new_config_node(raw_nominated_child, nominated_child)

    # 4. 终于轮到普通节点了
    if raw_node.is_fold:
        if not config_node.is_fold:
            # 4.1 因为有步骤2，只可能是raw_node已经自动折叠过，我们也让config强制自动折叠，这样两边就一致了，方便递归调用
            config_node.fold(False, True)
        else:
            # 4.2 两边都已经折叠了，待会自动同步就好了
            pass
    else:
        if config_node.is_fold:
            # 4.3 步骤2已经处理过
            pass
        else:
            # 4.4 两边都没有折叠过，都是普通节点列表，我们先同步一下
            for ordinary_value, ordinary_child in raw_node.ordinary_children.items():
                if ordinary_value in config_node.ordinary_children:
                    # 4.4.1 两边都存在，等待下一轮同步
                    pass
                else:
                    # 4.4.2 config里面没有，取消当前节点里面可能的配置信息，然后pass
                    ordinary_child.cancel_all_the_config_status_under_me()
                    pass
            for ordinary_value, ordinary_child in config_node.ordinary_children.items():
                if ordinary_value in raw_node.ordinary_children:
                    # 同4.4.1. 两边都存在
                    pass
                else:
                    # 4.4.3， 只有config里才有，新建立一个空节点
                    raw_node.assure_child_during_automation(ordinary_value)

    # 普通节点列表也准备好了，config的普通节点都已经出现在当前树种，递归进行下一轮
    for ordinary_value, ordinary_child in config_node.ordinary_children.items():
        raw_ordinary_child = raw_node.ordinary_children.get(ordinary_value)
        # 两边同步过，现在是肯定两边同时存在的
        sync_with_new_config_node(raw_ordinary_child, ordinary_child)


class URLTree(object):
    """
    URLTree, 所有操作从此接入
    """

    def __init__(self, version=0):
        self.root = URLTreeNode(0, '', None, False, True)
        self.synchronize_ts = -1
        self.version = version

    def reset(self, version):
        """
        重置节点

        :param version:
        """
        self.root = URLTreeNode(0, '', None, False, True)
        self.version = version

    def normalize_url(self, url):
        """
        增加一个新url, 并且返回规范化的url
        :param url: 用户的原始url
        :return: 规范化得url, 以及折叠生成的键值对
        """
        if not url:
            return '', dict()

        url_parts = url.split('/', -1)
        url_parts = filter(bool, url_parts)
        url_parts_len = len(url_parts)
        result_url_parts = []
        current_node = self.root
        folded_values = {}
        for current_node_depth, url_part in enumerate(url_parts):
            child_node = current_node.assure_child_during_automation(url_part)

            if current_node_depth == (url_parts_len - 1):
                child_node.mark_leaf()

            result_url_parts.append(child_node.value)
            if child_node.value == FOLD_FLAG:
                folded_values['fold_%d' % (current_node_depth + 1)] = url_part
            current_node = child_node

        return '/'.join(result_url_parts), folded_values

    def get_node_of_url(self, url, is_automation=True):
        """
        保证url能在tree中存在，并返回最终节点; 如果路径不存在，则生成.
        此函数只针对配置的url，所以假设生成的节点都应该是命名节点

        :param url:
        :param is_automation: 是否来自自动生成的数据
        :return: url对应的叶子节点
        """

        if not url:
            return ''

        url_parts = url.split('/', -1)
        url_parts = filter(bool, url_parts)
        current_node = self.root
        for depth, url_part in enumerate(url_parts):
            if current_node.disable_fold and url_part == FOLD_FLAG:
                # invalid config
                return None
            if is_automation:
                child_node = current_node.assure_child_during_automation(url_part)
            else:
                child_node = current_node.assure_child_during_config(url_part)
            if child_node is None:
                # 异常了
                return None

            current_node = child_node
        return current_node

    def get_exact_node_of_url(self, url):
        """
        严格匹配url，没有，则返回none
        :param url: 原始url
        :return: 对应的节点，完全匹配
        """

        if not url:
            return None

        url_parts = url.split('/', -1)
        url_parts = filter(bool, url_parts)
        current_node = self.root
        for depth, url_part in enumerate(url_parts):
            child_node = current_node.get_exact_child(url_part)
            if not child_node:
                return None
            current_node = child_node
        return current_node

    def get_visit_count(self, url):
        node = self.get_exact_node_of_url(url)
        if node is None:
            return 0

        return node.visit_count

    def update_disable_fold_url(self, disable_fold_url):
        """对于这些url disable fold.

        :param disable_fold_url: url配置必须准确匹配
        """

        # 对上一层禁止折叠, 这个一定是人工配置的
        node = self.get_node_of_url(disable_fold_url, is_automation=False)
        if node is None:
            # exception
            return
        node.unfold()
        node.disable_fold = True

    def update_fold_url(self, fold_url, is_automation=False):
        """对于这些url，强制fold

        :param fold_url: 我们严格找"www.host.com/$FOLD_FLAG/path1/$FOLD_FLAG", 我们只找最后一个，把它的父节点进行折叠, 中间的
                         请再写一遍
        :param is_automation: 折叠的规则，可能是人工指定的，也可能是自动生成，从server中同步到的，需要指明
        """

        # 每一层的折叠都要算上
        fold_parts = fold_url.rsplit('/', 1)
        if len(fold_parts) != 2 or fold_parts[-1] != FOLD_FLAG:
            # url不符合
            return

        sub_url = fold_parts[0]
        node = self.get_node_of_url(sub_url, is_automation=is_automation)
        if node is None:
            # exception
            return

        if not node.disable_fold:
            node.fold(True)
        else:
            # 可能之前标记disable了,这些优先级跟高
            pass

    def get_all_url(self, ):
        result = list()
        self.root.get_all_url_under_this_node('', result)
        return result

    def get_all_leaves_dict(self):
        result = dict()
        self.root.get_all_leaves_under_this_node('', result)
        return result

    def clean_visit_count(self):
        self.root.clean_visit_count()

    def get_all_fold_rule(self):
        result = list()
        self.root.get_all_fold_url('', result)
        return result

    def get_all_generated_rule(self):
        result = list()
        self.root.get_all_generated_fold_url('', result)
        return result

    def get_nodes_number(self):
        """
        获取当前url树种所有节点的数目
        """
        return self.root.get_nodes_under_me()

    def get_tree_string(self):
        """
        获取当前url树的图形表示
        """
        return self.root.get_subtree_string('', True, False)

    def synchronize(self, force=False):
        """
        synchronize with server
        :param force: 是否强制sync，默认false，隔一段时间；强制为测试方便
        :return: success state
        """

        now = millis_now()
        if not force and (now - self.synchronize_ts) < 300000:
            # 5 min for sync
            return
        self.synchronize_ts = now

        try:
            print 'url tree sync, the fold urls are: ', self.get_all_generated_rule()
            from complexconfig.configcontainer import configcontainer
            sniffer_config = configcontainer.get_config("sniffer")
            report_url = sniffer_config.get_string('sniffer.web_config.bones.report_url',
                                                   'http://127.0.0.1:8080/asset-manager/trunk/report')
            report_leaves_url = sniffer_config.get_string('sniffer.web_config.bones.page_count_report_url',
                                                          'http://127.0.0.1:8080/page_analysis/report_url')
            fetch_url = sniffer_config.get_string('sniffer.web_config.bones.fetch_url',
                                                  'http://127.0.0.1:8080/asset-manager/trunk/list')
            if not report_url or not fetch_url or not report_leaves_url:
                logger.error("bones url is not configured")
                return False

            # report first. Continue with failure.
            data = {
                'urls': self.get_all_generated_rule(),
                'version': self.version
            }
            print "data", data
            print "report_url....", report_url
            print "report_leaves_url...", report_leaves_url
            response = requests.post(report_url, json=data)
            print response.text
            if response.status_code != 200:
                logger.error('fail to send report with status: %s', response.status_code)
            else:
                try:
                    response_data = response.json()
                    if response_data.get('status') != 200:
                        logger.error('report server return failure, response is %s', response.text)
                except Exception as ex:
                    logger.error('report server return failure, exception is %s', ex)
            data = {
                'visit_times': self.get_all_leaves_dict(),
            }
            print "data2", data, type(data)
            response = requests.post(report_leaves_url, json=data)
            if response.status_code != 200:
                logger.error('fail to send leaves report with status: %s', response.status_code)
            else:
                try:
                    response_data = response.json()
                    if response_data.get('status') != 200:
                        logger.error('leaves report server return failure, response is %s', response.text)
                except Exception as ex:
                    logger.error('report server return failure, exception is %s', ex)

            self.clean_visit_count()

            # start to fetch, return with failure
            response = requests.get(fetch_url)
            if response.status_code != 200:
                logger.error('fail to fetch url from server with status: %s', response.status_code)
                return False
            else:
                try:
                    response_data = response.json()
                    if response_data.get('status') != 200:
                        logger.error('fetch url fail, the response is %s', response.text)
                        return False
                except Exception as ex:
                    logger.error('fetch url fail, the exception is %s', ex)
                    return False

            # data is fetched successfully
            result = response_data['result']
            version = response_data['version']
            trunks = result['trunks']
            blackTrunks = result['blackTrunks']
            whiteTrunks = result['whiteTrunks']

            if self.version != version:
                self.reset(version)

            self.sync_with_config(version, trunks, whiteTrunks, blackTrunks)
        except Exception as ex:
            logger.error('meet error during synchronization, error：%s', ex)
            import traceback;
            traceback.print_exc()
            return False

        return True

    def sync_with_config(self, version, trunks, whiteTrunks, blackTrunks):
        """
        当前树根配置生成的树进行合并
        """

        config_tree = URLTree(version)
        blackTrunks.sort()
        whiteTrunks.sort()
        trunks.sort()
        for url in whiteTrunks:
            config_tree.update_fold_url(url, is_automation=False)
        for url in blackTrunks:
            config_tree.update_disable_fold_url(url)
        for url in trunks:
            config_tree.update_fold_url(url, is_automation=True)
        sync_with_new_config_node(self.root, config_tree.root)
