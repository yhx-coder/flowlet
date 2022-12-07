# -*- coding: utf-8 -*-
# @author: ming
# @date: 2022/11/30 11:01
import logging
import pymysql
from dbutils.pooled_db import PooledDB


class DbHelper:
    def __init__(self, host, port, user, password, database, charset):
        self.pool = PooledDB(
            creator=pymysql,
            maxconnections=10,
            mincached=3,
            maxcached=4,
            blocking=True,
            maxusage=None,
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset=charset
        )

        self.logger = self.config_log()

    def config_log(self):
        logger = logging.getLogger("dbHelper")
        logger.setLevel(logging.WARNING)
        handler = logging.FileHandler(filename="db_log.txt", encoding="utf8")
        handler.setLevel(logging.WARNING)
        format_str = logging.Formatter("%(asctime)s - %(pathname)s[line:%(lineno)d] - %(message)s")
        handler.setFormatter(format_str)
        logger.addHandler(handler)
        return logger

    def select_one_simple(self, sql):
        """
        无参数版查询，相当于是 select_one 的少参重载。查询结果仅为一条记录时使用。
        :param sql:
        :return:
        """
        conn = self.pool.connection()
        cursor = conn.cursor()
        try:
            cursor.execute(sql)
            result = cursor.fetchone()
            return result
        except Exception as e:
            self.logger.error(e)
        finally:
            cursor.close()
            conn.close()

    def select_one(self, sql, values):
        """
        查询结果仅为一条记录时使用。
        :param sql:
        :param values:
        :return:
        """
        conn = self.pool.connection()
        cursor = conn.cursor()
        try:
            cursor.execute(sql, values)
            result = cursor.fetchone()
            return result
        except Exception as e:
            self.logger.error(e)
        finally:
            cursor.close()
            conn.close()

    def select_all_simple(self, sql):
        """
        查询结果为多条记录时使用。select_all的少参重载
        :param sql:
        :return:
        """
        conn = self.pool.connection()
        cursor = conn.cursor()
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            return results
        except Exception as e:
            self.logger.error(e)
        finally:
            cursor.close()
            conn.close()

    def select_all(self, sql, values):
        """
        查询结果为多条记录时使用。
        :param sql:
        :param values:
        :return:
        """
        conn = self.pool.connection()
        cursor = conn.cursor()
        try:
            cursor.execute(sql, values)
            results = cursor.fetchall()
            return results
        except Exception as e:
            self.logger.error(e)
        finally:
            cursor.close()
            conn.close()

    def select_one_value(self, sql, values):
        """
        查询结果仅为一个数
        :param sql:
        :param values:
        :return:
        """
        result = self.select_one(sql, values)
        if result is not None:
            return result[0]
        else:
            return -1

    def get_max_tele_round(self):
        """
        获取最大遥测轮次
        :return:
        """
        sql = "select max(CAST(telemetryRounds AS UNSIGNED)) from new_device_int_data"
        result = self.select_one_simple(sql)
        if result is not None:
            return result[0]
        else:
            return -1

    def get_link_bandwidth(self, s1, s2, tele_round):
        """
        获取提条链路被占用的带宽
        :param s1:
        :param s2:
        :param tele_round:
        :return:
        """
        sql = "select from_interface,to_interface from topo_interface where from_switch=%s and to_switch=%s"
        result = self.select_one(sql, (s1, s2))
        s1_egress = result[0]
        s2_ingress = result[1]
        s1_id = s1[1:]
        s2_id = s2[1:]
        bandwidth_sql = "select AVG(utilization) from new_device_int_data where switchId=%s and egressPort=%s and telemetryRounds=%s"
        s1_bandwidth_result = self.select_one(bandwidth_sql, (s1_id, s1_egress, tele_round))
        s1_bandwidth = 0 if s1_bandwidth_result is None else s1_bandwidth_result[0]
        s2_bandwidth_result = self.select_one(bandwidth_sql, (s2_id, s2_ingress, tele_round))
        s2_bandwidth = 0 if s2_bandwidth_result is None else s2_bandwidth_result[0]
        return max(s1_bandwidth, s2_bandwidth)

    def get_hopLatency(self, s1, tele_round):
        sql = "SELECT AVG(hopLatency) from new_device_int_data WHERE switchId=%s and telemetryRounds=%s"
        s1_id = s1[1:]
        return self.select_one_value(sql, (s1_id, tele_round))

    def get_deqQdepth(self, s1, tele_round):
        sql = "SELECT AVG(deqQdepth) from new_device_int_data WHERE switchId=%s and telemetryRounds=%s"
        s1_id = s1[1:]
        return self.select_one_value(sql, (s1_id, tele_round))

    def get_deqTimedelta(self, s1, tele_round):
        sql = "SELECT AVG(deqTimedelta) from new_device_int_data WHERE switchId=%s and telemetryRounds=%s"
        s1_id = s1[1:]
        return self.select_one_value(sql, (s1_id, tele_round))

    def get_link_latency(self, s1, s2, tele_round):
        s1_id = s1[1:]
        s2_id = s2[1:]
        sql = "SELECT curTime from new_device_int_data WHERE switchId=%s and telemetryRounds=%s"
        s1_curtime = self.select_one_value(sql, (s1_id, tele_round))
        s2_curtime = self.select_one_value(sql, (s2_id, tele_round))
        if s1_curtime > 0 and s2_curtime > 0:
            return abs(s1_curtime - s2_curtime)
        else:
            return -1

    def get_valid_max_tele_round(self):
        """
        获取遥测最大轮次。里面的探针无丢包。
        :return:
        """
        sql = "SELECT telemetryRounds from topo_state GROUP BY telemetryRounds " \
              "HAVING COUNT(DISTINCT packetId)=20 ORDER BY CAST(telemetryRounds as UNSIGNED) DESC LIMIT 1"

        result = self.select_one_simple(sql)
        if result is not None:
            return result[0]
        else:
            return -1

    def get_valid_tele_round(self):
        """
        获取所有有效的轮次
        :return:
        """
        sql = "SELECT telemetryRounds from topo_state GROUP BY telemetryRounds " \
              "HAVING COUNT(DISTINCT packetId)=20 ORDER BY CAST(telemetryRounds as UNSIGNED) DESC"
        results = self.select_all_simple(sql)
        round_list = []
        if len(results) != 0:
            for result in results:
                round_list.append(result[0])
        else:
            return round_list
