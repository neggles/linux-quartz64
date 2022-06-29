// SPDX-License-Identifier: GPL-2.0
/*
 * Rockchip RK806 Core (SPI) driver
 *
 * Copyright (c) 2021 Rockchip Electronics Co., Ltd.
 *
 * Author: Xu Shengfei <xsf@rock-chips.com>
 */

#include <linux/interrupt.h>
#include <linux/mfd/core.h>
#include <linux/mfd/rk808.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>

static const struct regmap_range rk806_volatile_ranges[] = {
	regmap_reg_range(RK806_POWER_EN0, RK806_POWER_EN5),
	regmap_reg_range(RK806_DVS_START_CTRL, RK806_INT_MSK1),
};

static const struct regmap_access_table rk806_volatile_table = {
	.yes_ranges = rk806_volatile_ranges,
	.n_yes_ranges = ARRAY_SIZE(rk806_volatile_ranges),
};

static const struct regmap_config rk806_regmap_config_spi = {
	.reg_bits = 8,
	.val_bits = 8,
	.cache_type = REGCACHE_RBTREE,
	.volatile_table = &rk806_volatile_table,
};

static int rk806_spi_bus_write(void *context, const void *vdata, size_t count)
{
	struct device *dev = context;
	struct spi_device *spi = to_spi_device(dev);
	const char *data = vdata;
	char buffer[4] = { 0 };

	/* implementation currently only supports single write */
	if (count != 2)
		return -EINVAL;

	buffer[0] = RK806_CMD_WRITE | (count - 2);
	buffer[1] = data[0]; /* register address */
	buffer[2] = RK806_REG_H;
	buffer[3] = data[1]; /* register value */

	return spi_write(spi, &buffer, sizeof(buffer));
}

static int rk806_spi_bus_read(void *context, const void *vreg, size_t reg_size,
			      void *val, size_t val_size)
{
	struct device *dev = context;
	struct spi_device *spi = to_spi_device(dev);
	const char *reg = vreg;
	char txbuf[3] = { 0 };

	if (reg_size != sizeof(char) || val_size < 1)
		return -EINVAL;

	txbuf[0] = RK806_CMD_READ | (val_size - 1);
	txbuf[1] = *reg;
	txbuf[2] = RK806_REG_H;

	return spi_write_then_read(spi, txbuf, sizeof(txbuf), val, val_size);
}

static const struct regmap_bus rk806_regmap_bus_spi = {
	.write = rk806_spi_bus_write,
	.read = rk806_spi_bus_read,
	.reg_format_endian_default = REGMAP_ENDIAN_NATIVE,
	.val_format_endian_default = REGMAP_ENDIAN_NATIVE,
};

static int rk8xx_spi_probe(struct spi_device *spi)
{
	struct regmap *regmap;

	regmap = devm_regmap_init(&spi->dev, &rk806_regmap_bus_spi,
				  &spi->dev, &rk806_regmap_config_spi);
	if (IS_ERR(regmap))
		return dev_err_probe(&spi->dev, PTR_ERR(regmap),
				     "Failed to initialize register map\n");

	return rk8xx_probe(&spi->dev, RK806_ID, spi->irq, regmap);
}

static const struct of_device_id rk8xx_spi_of_match[] = {
	{ .compatible = "rockchip,rk806", },
	{ }
};
MODULE_DEVICE_TABLE(of, rk8xx_spi_of_match);

static const struct spi_device_id rk8xx_spi_id_table[] = {
	{ "rk806", 0 },
	{ }
};
MODULE_DEVICE_TABLE(spi, rk8xx_spi_id_table);

static struct spi_driver rk8xx_spi_driver = {
	.driver		= {
		.name	= "rk8xx-spi",
		.of_match_table = rk8xx_spi_of_match,
	},
	.probe		= rk8xx_spi_probe,
	.id_table	= rk8xx_spi_id_table,
};
module_spi_driver(rk8xx_spi_driver);

MODULE_AUTHOR("Xu Shengfei <xsf@rock-chips.com>");
MODULE_DESCRIPTION("RK8xx SPI PMIC driver");
MODULE_LICENSE("GPL v2");
